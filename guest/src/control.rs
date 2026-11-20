//! Concurrent agent sockets over a private, flow-controlled virtio-serial link.
//!
//! Shared by the host and guest. Socket pairs preserve the agent's existing
//! deadlines, half-close and attachment cancellation semantics. Yamux bounds
//! receive buffering and prevents a stalled stream from blocking other requests.
use std::fs::File;
use std::future::Future;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::mpsc::{self, SyncSender};
use std::sync::Mutex;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::future::poll_fn;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc as channel, watch};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

const STREAMS: usize = 64;
pub const PORT_NAME: &str = "org.flexvm.control";
type Reply = SyncSender<io::Result<UnixStream>>;
struct Open {
    reply: Reply,
    deadline: Instant,
}

struct Pending {
    open: Open,
    timer: Pin<Box<tokio::time::Sleep>>,
}

pub struct Client {
    requests: channel::Sender<Open>,
    stop: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

pub struct IncomingRequest {
    peer: UnixStream,
    payload: mpsc::Receiver<()>,
}

impl IncomingRequest {
    /// Keep dispatch order while the bridge negotiates the stream. The guest's
    /// request-line timeout starts only after a request byte reaches the socket.
    pub fn wait_for_payload(self) -> Option<UnixStream> {
        self.payload.recv().ok().map(|()| self.peer)
    }
}

impl Client {
    pub fn connect(io: UnixStream) -> io::Result<Self> {
        let runtime = runtime()?;
        io.set_nonblocking(true)?;
        let entered = runtime.enter();
        let io = tokio::net::UnixStream::from_std(io)?;
        drop(entered);
        let (requests, incoming) = channel::channel(STREAMS);
        let (stop, stopped) = watch::channel(false);
        let thread = std::thread::Builder::new().name("serial-control".into()).spawn(move || {
            let _ = runtime.block_on(drive(io, Some(incoming), None, stopped));
        })?;
        Ok(Self { requests, stop, thread: Some(thread) })
    }

    pub fn open(&self, deadline: Instant) -> io::Result<UnixStream> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let (reply, answer) = mpsc::sync_channel(1);
        self.requests.try_send(Open { reply, deadline }).map_err(|e| match e {
            channel::error::TrySendError::Full(_) => io::Error::new(io::ErrorKind::WouldBlock, "serial control request queue is full"),
            channel::error::TrySendError::Closed(_) => io::Error::new(io::ErrorKind::BrokenPipe, "serial control disconnected"),
        })?;
        answer.recv_timeout(left).map_err(|e| match e {
            mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
            mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe,
        })?
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()
}

/// Virtio RX can arrive before the deferred host-open control message. Confirm
/// the live peer through current poll state or successful TX before treating EOF
/// as the end of a connection; received bytes alone are insufficient.
struct Serial {
    fd: tokio::io::unix::AsyncFd<File>,
    connected: bool,
    retry: Pin<Box<tokio::time::Sleep>>,
}

impl Serial {
    fn new(fd: tokio::io::unix::AsyncFd<File>) -> Self {
        Self { fd, connected: false, retry: Box::pin(tokio::time::sleep(Duration::from_millis(10))) }
    }

    fn confirm_connection(&mut self) -> io::Result<()> {
        if !self.connected && !hung_up(self.fd.as_raw_fd())? {
            self.connected = true;
        }
        Ok(())
    }

    fn wait<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        // Tokio retains closed readiness permanently, but virtio-serial HUP
        // means a reconnectable host peer. Its nonblocking I/O can still return
        // EAGAIN. Yield and arrange a retry instead of spinning on cached HUP.
        if self.retry.as_mut().poll(cx).is_ready() {
            self.retry.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(10));
            let _ = self.retry.as_mut().poll(cx);
        }
        Poll::Pending
    }
}

impl AsyncRead for Serial {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.confirm_connection()?;
        loop {
            let mut ready = std::task::ready!(this.fd.poll_read_ready_mut(cx))?;
            match ready.try_io(|fd| fd.get_mut().read(buf.initialize_unfilled())) {
                Ok(Ok(0)) if !this.connected => {
                    ready.clear_ready();
                    drop(ready);
                    return this.wait(cx);
                }
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_) => {
                    drop(ready);
                    return this.wait(cx);
                }
            }
        }
    }
}

impl AsyncWrite for Serial {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.confirm_connection()?;
        loop {
            let mut ready = std::task::ready!(this.fd.poll_write_ready_mut(cx))?;
            match ready.try_io(|fd| fd.get_mut().write(buf)) {
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Ok(n)) => {
                    this.connected |= n != 0;
                    return Poll::Ready(Ok(n));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => {
                    drop(ready);
                    // A disconnected virtio port reports HUP while writes
                    // return EAGAIN. End an established parser so it can reset.
                    if this.connected && hung_up(this.fd.as_raw_fd())? {
                        return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                    }
                    return this.wait(cx);
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub fn serve(port: File, incoming: SyncSender<IncomingRequest>) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(port.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(port.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    runtime()?.block_on(async {
        // File owns the descriptor; it is never replaced or closed separately
        // while registered with the reactor.
        let fd = unsafe { tokio::io::unix::AsyncFd::register(port)? };
        let io = Serial::new(fd);
        let (_alive, stop) = watch::channel(false);
        drive(io, None, Some(incoming), stop).await
    })
}

enum Event {
    Open(yamux::Stream, Open),
    Incoming(yamux::Stream),
    End(io::Result<()>),
}

async fn drive<T>(
    io: T,
    mut requests: Option<channel::Receiver<Open>>,
    incoming: Option<SyncSender<IncomingRequest>>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut config = yamux::Config::default();
    config.set_max_num_streams(STREAMS).set_max_connection_receive_window(Some(STREAMS * 256 * 1024)).set_split_send_size(16 * 1024);
    let mode = if requests.is_some() { yamux::Mode::Client } else { yamux::Mode::Server };
    let mut connection = yamux::Connection::new(io.compat(), config, mode);
    let mut pending = None;
    loop {
        // Both operations must be polled: creating streams alone does not drive
        // Yamux's I/O, window updates or the existing stream bridges.
        let event = tokio::select! {
            _ = stop.changed() => {
                // A device disconnect is not reliably surfaced as EOF by every
                // virtio-serial implementation. Explicitly terminate the old
                // parser on the wire before closing the host character device.
                let _ = tokio::time::timeout(Duration::from_secs(1), poll_fn(|cx| connection.poll_close(cx))).await;
                return Ok(());
            },
            event = poll_fn(|cx| {
                if pending.is_none() {
                    if let Some(requests) = &mut requests {
                        match requests.poll_recv(cx) {
                            Poll::Ready(Some(open)) => {
                                let timer = Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(open.deadline)));
                                pending = Some(Pending { open, timer });
                            }
                            Poll::Ready(None) => return Poll::Ready(Event::End(Ok(()))),
                            Poll::Pending => {}
                        }
                    }
                }
                if pending.as_mut().is_some_and(|p| p.timer.as_mut().poll(cx).is_ready()) {
                    let _ = pending.take().unwrap().open.reply.send(Err(io::ErrorKind::TimedOut.into()));
                    cx.waker().wake_by_ref();
                } else if pending.is_some() {
                    match connection.poll_new_outbound(cx) {
                        Poll::Ready(Ok(stream)) => return Poll::Ready(Event::Open(stream, pending.take().unwrap().open)),
                        Poll::Ready(Err(e)) => {
                            let kind = if matches!(e, yamux::ConnectionError::TooManyStreams) { io::ErrorKind::WouldBlock } else { io::ErrorKind::BrokenPipe };
                            let _ = pending.take().unwrap().open.reply.send(Err(io::Error::new(kind, e)));
                            cx.waker().wake_by_ref();
                        }
                        Poll::Pending => {}
                    }
                }
                match connection.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(stream))) => Poll::Ready(Event::Incoming(stream)),
                    Poll::Ready(Some(Err(e))) => Poll::Ready(Event::End(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)))),
                    Poll::Ready(None) => Poll::Ready(Event::End(Ok(()))),
                    Poll::Pending => Poll::Pending,
                }
            }) => event,
        };
        match event {
            Event::End(result) => return result,
            Event::Open(stream, reply) => {
                bridge(stream, Endpoint::Outgoing(reply));
            }
            Event::Incoming(stream) => {
                let Some(incoming) = &incoming else {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "guest opened an unsolicited control stream"));
                };
                bridge(stream, Endpoint::Incoming(incoming.clone()));
            }
        }
    }
}

/// Shared polling handles, like an I/O split, also allow the cancellation
/// watcher to inspect closure while a direction is backpressured. The mutex
/// is held only during a nonblocking poll, never across an await.
struct Shared<T>(Arc<Mutex<T>>);
impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for Shared<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Shared<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_shutdown(cx)
    }
}

enum Endpoint {
    Outgoing(Open),
    Incoming(SyncSender<IncomingRequest>),
}

/// Record framing preserves Unix write-half closure without sending Yamux FIN.
/// Yamux does not reset a dropped stream after FIN until the peer writes again;
/// keeping it open lets full cancellation promptly reset even a silent peer.
/// Empty records mean EOF, while data records are bounded to one frame.
struct Channel {
    framed: Framed<tokio_util::compat::Compat<yamux::Stream>, LengthDelimitedCodec>,
    buffered: BytesMut,
    read_eof: bool,
    write_eof: bool,
}

impl Channel {
    fn new(stream: yamux::Stream) -> Self {
        let codec = LengthDelimitedCodec::builder().little_endian().max_frame_length(16 * 1024).new_codec();
        Self { framed: Framed::new(stream.compat(), codec), buffered: BytesMut::new(), read_eof: false, write_eof: false }
    }
}

impl AsyncRead for Channel {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !this.buffered.is_empty() {
            let n = this.buffered.len().min(buf.remaining());
            buf.put_slice(&this.buffered[..n]);
            this.buffered.advance(n);
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut this.framed).poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if this.read_eof {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "control record after EOF")));
                }
                if frame.is_empty() {
                    this.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                this.buffered = frame;
                let n = this.buffered.len().min(buf.remaining());
                buf.put_slice(&this.buffered[..n]);
                this.buffered.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending if this.read_eof => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Channel {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_eof {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(Sink::<Bytes>::poll_ready(Pin::new(&mut this.framed), cx))?;
        let n = buf.len().min(16 * 1024);
        Pin::new(&mut this.framed).start_send(Bytes::copy_from_slice(&buf[..n]))?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::<Bytes>::poll_flush(Pin::new(&mut self.get_mut().framed), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_eof {
            std::task::ready!(Sink::<Bytes>::poll_ready(Pin::new(&mut this.framed), cx))?;
            Pin::new(&mut this.framed).start_send(Bytes::new())?;
            this.write_eof = true;
        }
        Sink::<Bytes>::poll_flush(Pin::new(&mut this.framed), cx)
    }
}

/// Drain each direction before acting on EOF. Returning a synthetic read error
/// at EOF could discard bytes already buffered by the copier.
#[derive(Clone, Copy)]
enum Side {
    Client,
    Agent,
}

async fn forward(io: &mut tokio::net::UnixStream, stream: &mut Channel, side: Side) -> io::Result<()> {
    let local = Shared(Arc::new(Mutex::new(io)));
    let remote = Shared(Arc::new(Mutex::new(stream)));
    let drained = AtomicBool::new(false);
    let mut input = local.clone();
    let mut output = local.clone();
    let mut received = remote.clone();
    let mut sent = remote.clone();
    let outgoing = async {
        tokio::io::copy(&mut input, &mut sent).await?;
        sent.flush().await?;
        drained.store(true, Ordering::Relaxed);
        if hung_up(local.0.lock().unwrap().as_raw_fd())? {
            return Ok::<_, io::Error>(true);
        }
        sent.shutdown().await?;
        Ok(false)
    };
    let incoming = async {
        tokio::io::copy(&mut received, &mut output).await?;
        output.flush().await?;
        if remote.0.lock().unwrap().framed.get_ref().get_ref().is_closed() {
            return Ok::<_, io::Error>(true);
        }
        output.shutdown().await?;
        Ok(false)
    };
    let cancellation = async {
        loop {
            let local_closed = hung_up(local.0.lock().unwrap().as_raw_fd())?;
            let cancelled = match side {
                // The caller is gone, so buffered request input may be discarded.
                Side::Client => local_closed,
                // Preserve a finished agent's buffered response. A client reset,
                // however, must interrupt even a backpressured request writer.
                Side::Agent => remote.0.lock().unwrap().framed.get_ref().get_ref().is_closed() || (local_closed && drained.load(Ordering::Relaxed)),
            };
            if cancelled {
                return Ok::<_, io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    tokio::pin!(outgoing, incoming, cancellation);
    tokio::select! {
        result = &mut outgoing => match result {
            Ok(true) => Ok(()),
            Ok(false) => {
                tokio::select! { result = &mut incoming => { result?; }, result = &mut cancellation => result?, }
                Ok(())
            }
            // A remote reset after sending a reply fails client writes with
            // WriteZero while the response is still buffered to drain.
            Err(_) if matches!(side, Side::Client) => {
                tokio::select! { result = &mut incoming => { result?; }, result = &mut cancellation => result?, }
                Ok(())
            }
            Err(error) => Err(error),
        },
        result = &mut incoming => match result {
            Ok(true) => Ok(()),
            Ok(false) => {
                tokio::select! { result = &mut outgoing => { result?; }, result = &mut cancellation => result?, }
                Ok(())
            }
            // An early agent reply and close fails incoming writes with EPIPE
            // while the reply is still buffered in the local socket pair.
            Err(_) if matches!(side, Side::Agent) => {
                tokio::select! { result = &mut outgoing => { result?; }, result = &mut cancellation => result?, }
                Ok(())
            }
            Err(error) => Err(error),
        },
        result = &mut cancellation => result,
    }
}

pub(crate) fn hung_up(fd: std::os::fd::RawFd) -> io::Result<bool> {
    let mut poll = libc::pollfd { fd, events: 0, revents: 0 };
    loop {
        if unsafe { libc::poll(&mut poll, 1, 0) } >= 0 {
            return Ok(poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

fn bridge(stream: yamux::Stream, endpoint: Endpoint) {
    const HELLO: &[u8; 4] = b"FVS\x01";
    let pair = (|| -> io::Result<_> {
        let (peer, io) = UnixStream::pair()?;
        io.set_nonblocking(true)?;
        Ok((peer, tokio::net::UnixStream::from_std(io)?))
    })();
    let (peer, mut io) = match pair {
        Ok(pair) => pair,
        Err(e) => {
            if let Endpoint::Outgoing(open) = endpoint {
                let _ = open.reply.send(Err(e));
            }
            return;
        }
    };
    match endpoint {
        Endpoint::Outgoing(open) => {
            let Open { reply, deadline } = open;
            tokio::spawn(async move {
                let mut stream = Channel::new(stream);
                // Do not expose the socket until the guest has queued it with
                // its ordered dispatcher. A timed-out earlier request cannot
                // arrive after a later retry just because its SYN was delayed.
                let handshake = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
                    stream.write_all(HELLO).await?;
                    stream.flush().await?;
                    let mut ack = [0; 4];
                    stream.read_exact(&mut ack).await?;
                    if &ack != HELLO {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported serial control protocol"));
                    }
                    Ok(())
                })
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
                if let Err(e) = handshake {
                    let _ = reply.send(Err(e));
                    return;
                }
                if reply.send(Ok(peer)).is_ok() {
                    let _ = forward(&mut io, &mut stream, Side::Client).await;
                }
            });
        }
        Endpoint::Incoming(incoming) => {
            let (ready, payload) = mpsc::channel();
            if incoming.try_send(IncomingRequest { peer, payload }).is_err() {
                return;
            }
            tokio::spawn(async move {
                let mut stream = Channel::new(stream);
                let handshake = tokio::time::timeout(Duration::from_secs(5), async {
                    let mut hello = [0; 4];
                    stream.read_exact(&mut hello).await?;
                    if &hello != HELLO {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    stream.write_all(HELLO).await?;
                    stream.flush().await?;
                    let mut first = [0];
                    stream.read_exact(&mut first).await?;
                    io.write_all(&first).await
                })
                .await;
                if !matches!(handshake, Ok(Ok(()))) || ready.send(()).is_err() {
                    return;
                }
                let _ = forward(&mut io, &mut stream, Side::Agent).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::Duration;

    fn pair() -> (Client, mpsc::Receiver<IncomingRequest>, mpsc::Receiver<io::Result<()>>) {
        let (host, guest) = UnixStream::pair().unwrap();
        guest.set_nonblocking(true).unwrap();
        let (incoming, requests) = mpsc::sync_channel(STREAMS);
        let (finished, done) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = finished.send(serve(File::from(OwnedFd::from(guest)), incoming));
        });
        (Client::connect(host).unwrap(), requests, done)
    }

    fn open(client: &Client, requests: &mpsc::Receiver<IncomingRequest>) -> (UnixStream, UnixStream) {
        let mut host = client.open(Instant::now() + Duration::from_secs(3)).unwrap();
        host.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        host.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        // Yamux sends the stream's SYN with its first data/window frame.
        host.write_all(b"x").unwrap();
        let mut guest = requests.recv_timeout(Duration::from_secs(3)).unwrap().wait_for_payload().unwrap();
        guest.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        guest.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut first = [0];
        guest.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"x");
        (host, guest)
    }

    struct Fifo(std::path::PathBuf);

    impl Fifo {
        fn new() -> (Self, File) {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "flexvm-serial-reconnect-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            let reader = File::options().read(true).custom_flags(libc::O_NONBLOCK).open(&path).unwrap();
            (Self(path), reader)
        }

        fn writer(&self) -> File {
            File::options().write(true).custom_flags(libc::O_NONBLOCK).open(&self.0).unwrap()
        }
    }

    impl Drop for Fifo {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn serial_reconnect_does_not_spin_on_cached_hangup_readiness() {
        let (fifo, reader) = Fifo::new();
        drop(fifo.writer());
        runtime().unwrap().block_on(async {
            let fd = unsafe { tokio::io::unix::AsyncFd::register(reader).unwrap() };
            // Cache HUP, then reconnect the FIFO. The descriptor is unchanged,
            // but reads now return EAGAIN: the same transition as virtio-serial.
            fd.readable().await.unwrap().clear_ready();
            let mut writer = fifo.writer();
            let writing = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                writer.write_all(b"x")?;
                Ok::<_, io::Error>(writer)
            });
            let mut serial = Serial::new(fd);
            let mut bytes = [0];
            fn cpu_time() -> u64 {
                let mut time = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) }, 0);
                time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
            }
            let before = cpu_time();
            let result = tokio::time::timeout(Duration::from_millis(30), serial.read(&mut bytes)).await;
            let cpu_ns = cpu_time() - before;
            let writer = writing.join().unwrap().unwrap();
            assert!(cpu_ns < 10_000_000, "idle serial read burned {cpu_ns} ns of thread CPU in a 30 ms wait");
            // A heavily descheduled test thread may see data before polling
            // its expired timer. Either outcome must retain the byte exactly once.
            match result {
                Err(_) => assert_eq!(serial.read(&mut bytes).await.unwrap(), 1),
                Ok(read) => assert_eq!(read.unwrap(), 1),
            }
            assert_eq!(&bytes, b"x");
            drop(writer);
            assert_eq!(serial.read(&mut bytes).await.unwrap(), 0);
        });
    }

    #[test]
    fn buffered_rx_does_not_confirm_a_reconnected_peer() {
        let (fifo, reader) = Fifo::new();
        let mut first = fifo.writer();
        first.write_all(b"x").unwrap();
        drop(first);
        runtime().unwrap().block_on(async {
            let fd = unsafe { tokio::io::unix::AsyncFd::register(reader).unwrap() };
            let mut serial = Serial::new(fd);
            let mut bytes = [0];
            assert_eq!(serial.read(&mut bytes).await.unwrap(), 1);
            assert_eq!(&bytes, b"x");
            // Data arrived before the kernel's open state, modeled by buffered
            // FIFO data plus HUP. A later writer represents the deferred open.
            let path = fifo.0.clone();
            let writing = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                let mut writer = File::options().write(true).custom_flags(libc::O_NONBLOCK).open(path)?;
                writer.write_all(b"y")?;
                Ok::<_, io::Error>(writer)
            });
            let result = tokio::time::timeout(Duration::from_millis(30), serial.read(&mut bytes)).await;
            let writer = writing.join().unwrap().unwrap();
            match result {
                Err(_) => assert_eq!(serial.read(&mut bytes).await.unwrap(), 1),
                Ok(read) => assert_eq!(read.unwrap(), 1, "buffered RX incorrectly turned pre-open EOF into disconnect"),
            }
            assert_eq!(&bytes, b"y");
            drop(writer);
            assert_eq!(serial.read(&mut bytes).await.unwrap(), 0);
        });
    }

    #[test]
    fn client_shutdown_sends_goaway_before_device_disconnect() {
        let (host, mut device) = UnixStream::pair().unwrap();
        device.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let client = Client::connect(host).unwrap();
        drop(client);
        let mut saw_goaway = false;
        for _ in 0..8 {
            let mut header = [0; 12];
            device.read_exact(&mut header).unwrap();
            if header[1] == 3 {
                assert_eq!(header, [0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                saw_goaway = true;
                break;
            }
            // Yamux may have queued its initial keepalive before cancellation.
            assert_eq!(header[1], 2, "unexpected non-ping frame before shutdown");
        }
        assert!(saw_goaway, "transport closed without a protocol shutdown");
        assert_eq!(device.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn half_close_preserves_the_response_direction() {
        let (client, requests, done) = pair();
        let (mut host, mut guest) = open(&client, &requests);
        host.write_all(b"request body").unwrap();
        host.shutdown(Shutdown::Write).unwrap();
        let mut body = Vec::new();
        guest.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"request body");
        guest.write_all(b"response").unwrap();
        guest.shutdown(Shutdown::Write).unwrap();
        body.clear();
        host.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"response");
        drop(client);
        done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
    }

    #[test]
    fn requests_are_accepted_before_later_sockets_can_overtake_them() {
        let (client, requests, done) = pair();
        let mut first = client.open(Instant::now() + Duration::from_secs(3)).unwrap();
        let mut second = client.open(Instant::now() + Duration::from_secs(3)).unwrap();
        second.write_all(b"second").unwrap();
        first.write_all(b"first").unwrap();
        let mut a = requests.recv_timeout(Duration::from_secs(3)).unwrap().wait_for_payload().unwrap();
        let mut b = requests.recv_timeout(Duration::from_secs(3)).unwrap().wait_for_payload().unwrap();
        a.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut bytes = [0; 5];
        a.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"first");
        let mut bytes = [0; 6];
        b.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"second");
        drop(client);
        done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
    }

    #[test]
    fn an_acknowledged_stream_waits_for_request_bytes_before_dispatch() {
        let (client, requests, done) = pair();
        let mut host = client.open(Instant::now() + Duration::from_secs(3)).unwrap();
        let pending = requests.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(pending.payload.try_recv(), Err(mpsc::TryRecvError::Empty));
        host.write_all(b"PING\n").unwrap();
        let mut guest = pending.wait_for_payload().unwrap();
        guest.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut request = [0; 5];
        guest.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"PING\n");

        let silent = client.open(Instant::now() + Duration::from_secs(3)).unwrap();
        let pending = requests.recv_timeout(Duration::from_secs(3)).unwrap();
        drop(silent);
        assert!(pending.wait_for_payload().is_none());
        drop(client);
        done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
    }

    #[test]
    fn a_stalled_receiver_does_not_block_another_stream() {
        let (client, requests, done) = pair();
        let (_stalled, mut producer) = open(&client, &requests);
        let (started, producing) = mpsc::sync_channel(1);
        let writer = std::thread::spawn(move || {
            started.send(()).unwrap();
            let _ = producer.write_all(&vec![7; 8 << 20]);
        });
        producing.recv_timeout(Duration::from_secs(3)).unwrap();
        let (mut host, mut guest) = open(&client, &requests);
        guest.write_all(b"pong").unwrap();
        let mut reply = [0; 4];
        host.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong");
        drop(client);
        let closed = done.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(closed.is_ok() || closed.is_err_and(|e| e.kind() == io::ErrorKind::BrokenPipe));
        writer.join().unwrap();
    }

    #[test]
    fn stopping_the_owner_closes_live_agent_sockets() {
        let (client, requests, done) = pair();
        let (mut host, mut guest) = open(&client, &requests);
        drop(client);
        assert_eq!(host.read(&mut [0]).unwrap(), 0);
        assert_eq!(guest.read(&mut [0]).unwrap(), 0);
        done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
    }

    #[test]
    fn dropping_one_request_resets_its_peer_without_stopping_the_owner() {
        let (client, requests, done) = pair();
        let (host, guest) = open(&client, &requests);
        drop(host);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut fd = libc::pollfd { fd: guest.as_raw_fd(), events: 0, revents: 0 };
            assert!(unsafe { libc::poll(&mut fd, 1, 0) } >= 0);
            if fd.revents & libc::POLLHUP != 0 {
                break;
            }
            assert!(Instant::now() < deadline, "a disconnected client kept the agent socket open");
            std::thread::sleep(Duration::from_millis(1));
        }
        let (mut next, mut peer) = open(&client, &requests);
        peer.write_all(b"ok").unwrap();
        let mut bytes = [0; 2];
        next.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ok");
        drop(client);
        done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
    }

    #[test]
    fn a_full_dispatch_queue_resets_new_opens_and_recovers_after_draining() {
        let (host, guest) = UnixStream::pair().unwrap();
        let client = Client::connect(host).unwrap();
        let (incoming, requests) = mpsc::sync_channel::<IncomingRequest>(1);
        let server = std::thread::spawn(move || serve(File::from(OwnedFd::from(guest)), incoming));
        let first = client.open(Instant::now() + Duration::from_secs(3)).unwrap();
        let error = client.open(Instant::now() + Duration::from_secs(3)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let first_peer = requests.recv_timeout(Duration::from_secs(3)).unwrap();
        let mut next = client.open(Instant::now() + Duration::from_secs(3)).unwrap();
        next.write_all(b"x").unwrap();
        let mut peer = requests.recv_timeout(Duration::from_secs(3)).unwrap().wait_for_payload().unwrap();
        next.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.write_all(b"ok").unwrap();
        let mut reply = [0; 2];
        next.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ok");
        drop((first, first_peer, client));
        let closed = server.join().unwrap();
        assert!(closed.is_ok() || closed.is_err_and(|error| error.kind() == io::ErrorKind::BrokenPipe));
    }

    #[test]
    fn timed_out_opens_release_capacity_when_the_peer_resumes() {
        let (host, guest) = UnixStream::pair().unwrap();
        let client = Client::connect(host).unwrap();
        // No peer protocol is running yet. More than a full connection's worth
        // of timed-out handshakes must not permanently consume its stream IDs.
        for _ in 0..STREAMS + 8 {
            let error = client.open(Instant::now() + Duration::from_millis(10)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        }
        let (incoming, requests) = mpsc::sync_channel::<IncomingRequest>(STREAMS);
        let server = std::thread::spawn(move || serve(File::from(OwnedFd::from(guest)), incoming));
        let handler = std::thread::spawn(move || {
            for mut request in requests.into_iter().filter_map(IncomingRequest::wait_for_payload) {
                request.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                if request.read_exact(&mut [0]).is_ok() {
                    let _ = request.write_all(b"ok");
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut live = loop {
            match client.open(deadline) {
                Ok(live) => break live,
                // The delayed peer can fill its ordered dispatch queue before
                // the handler drains canceled requests. A reset is transient;
                // recovery must still finish within the original deadline.
                Err(error) if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::WouldBlock) && Instant::now() < deadline => {
                    std::thread::yield_now();
                }
                Err(error) => panic!("capacity did not recover: {error}"),
            }
        };
        live.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        live.write_all(b"x").unwrap();
        let mut reply = [0; 2];
        live.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ok");
        drop(client);
        let _ = server.join().unwrap();
        handler.join().unwrap();
    }

    #[test]
    fn a_full_close_drains_buffered_output_before_resetting() {
        let (client, requests, done) = pair();
        let (mut host, mut guest) = open(&client, &requests);
        let writer = std::thread::spawn(move || {
            guest.write_all(&vec![b'a'; (512 << 10) + 17]).unwrap();
            // Full close, rather than shutdown(Write), while output is queued.
        });
        let mut bytes = Vec::new();
        host.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, vec![b'a'; (512 << 10) + 17]);
        writer.join().unwrap();
        drop(client);
        done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
    }

    #[test]
    fn a_later_full_close_also_ends_a_half_closed_request() {
        let (client, requests, done) = pair();
        let (host, mut guest) = open(&client, &requests);
        host.shutdown(Shutdown::Write).unwrap();
        assert_eq!(guest.read(&mut [0]).unwrap(), 0);
        drop(host);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut fd = libc::pollfd { fd: guest.as_raw_fd(), events: 0, revents: 0 };
            assert!(unsafe { libc::poll(&mut fd, 1, 0) } >= 0);
            if fd.revents & libc::POLLHUP != 0 {
                break;
            }
            assert!(Instant::now() < deadline, "half-closed attachment survived its client");
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(client);
        done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
    }

    #[test]
    fn client_drains_buffered_reply_when_write_hits_remote_reset() {
        runtime().unwrap().block_on(async {
            let (host_wire, guest_wire) = UnixStream::pair().unwrap();
            host_wire.set_nonblocking(true).unwrap();
            guest_wire.set_nonblocking(true).unwrap();
            let host_wire = tokio::net::UnixStream::from_std(host_wire).unwrap();
            let guest_wire = tokio::net::UnixStream::from_std(guest_wire).unwrap();
            let mut client_conn = yamux::Connection::new(host_wire.compat(), yamux::Config::default(), yamux::Mode::Client);
            let mut server_conn = yamux::Connection::new(guest_wire.compat(), yamux::Config::default(), yamux::Mode::Server);

            let client_stream = poll_fn(|cx| client_conn.poll_new_outbound(cx)).await.unwrap();
            let mut client_ch = Channel::new(client_stream);
            client_ch.write_all(b"hi").await.unwrap();
            client_ch.flush().await.unwrap();

            let server_task = tokio::spawn(async move {
                let server_stream = poll_fn(|cx| server_conn.poll_next_inbound(cx)).await.unwrap().unwrap();
                let reply_task = tokio::spawn(async move {
                    let mut server_ch = Channel::new(server_stream);
                    let mut buf = [0; 2];
                    server_ch.read_exact(&mut buf).await.unwrap();
                    server_ch.write_all(b"error: reply").await.unwrap();
                    server_ch.flush().await.unwrap();
                    // Dropping server_ch sends RST right after the reply frame.
                });
                while let Some(Ok(_)) = poll_fn(|cx| server_conn.poll_next_inbound(cx)).await {}
                reply_task.await.unwrap();
            });

            let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
            let client_driver = tokio::spawn(async move {
                let mut closed_tx = Some(closed_tx);
                loop {
                    let _ = tokio::time::timeout(Duration::from_millis(5), poll_fn(|cx| client_conn.poll_next_inbound(cx))).await;
                    if let Some(tx) = closed_tx.take() {
                        if tx.send(()).is_err() {
                            break;
                        }
                    }
                    break;
                }
                while let Some(Ok(_)) = poll_fn(|cx| client_conn.poll_next_inbound(cx)).await {}
            });
            let _ = closed_rx.await;
            // Wait until the client stream has buffered both the reply and RST.
            let until = Instant::now() + Duration::from_secs(3);
            while !client_ch.framed.get_ref().get_ref().is_closed() {
                assert!(Instant::now() < until, "client stream did not observe remote reset");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            let (mut peer, io) = UnixStream::pair().unwrap();
            io.set_nonblocking(true).unwrap();
            let mut io = tokio::net::UnixStream::from_std(io).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            // Client already queued its request into the local socket pair before
            // forward() polls outgoing against the reset Yamux stream.
            peer.write_all(b"FENCE 2 123\n").unwrap();
            let _ = forward(&mut io, &mut client_ch, Side::Client).await;
            drop(io);
            drop(client_ch);
            let mut reply = [0; 12];
            peer.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"error: reply");
            client_driver.abort();
            server_task.abort();
        });
    }

    #[test]
    fn agent_drains_buffered_reply_when_incoming_write_hits_local_close() {
        runtime().unwrap().block_on(async {
            let (host_wire, guest_wire) = UnixStream::pair().unwrap();
            host_wire.set_nonblocking(true).unwrap();
            guest_wire.set_nonblocking(true).unwrap();
            let host_wire = tokio::net::UnixStream::from_std(host_wire).unwrap();
            let guest_wire = tokio::net::UnixStream::from_std(guest_wire).unwrap();
            let mut client_conn = yamux::Connection::new(host_wire.compat(), yamux::Config::default(), yamux::Mode::Client);
            let mut server_conn = yamux::Connection::new(guest_wire.compat(), yamux::Config::default(), yamux::Mode::Server);

            let client_stream = poll_fn(|cx| client_conn.poll_new_outbound(cx)).await.unwrap();
            let mut client_ch = Channel::new(client_stream);
            client_ch.write_all(b"extra request body").await.unwrap();
            client_ch.flush().await.unwrap();

            let client_driver = tokio::spawn(async move {
                while let Some(Ok(_)) = poll_fn(|cx| client_conn.poll_next_inbound(cx)).await {}
            });

            let server_stream = poll_fn(|cx| server_conn.poll_next_inbound(cx)).await.unwrap().unwrap();
            let server_driver = tokio::spawn(async move {
                while let Some(Ok(_)) = poll_fn(|cx| server_conn.poll_next_inbound(cx)).await {}
            });

            let mut server_ch = Channel::new(server_stream);
            // Wait until the server stream has buffered the client's extra request
            // bytes, so incoming immediately hits EPIPE on its first write to io.
            let mut first = [0];
            server_ch.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"e");
            // Agent wrote a multi-chunk reply and closed its local socket before
            // consuming the remaining request bytes.
            let expected = vec![b'r'; 64 * 1024];
            let (mut peer, io) = UnixStream::pair().unwrap();
            io.set_nonblocking(true).unwrap();
            let mut io = tokio::net::UnixStream::from_std(io).unwrap();
            peer.write_all(&expected).unwrap();
            drop(peer);

            let _ = forward(&mut io, &mut server_ch, Side::Agent).await;
            drop(io);
            drop(server_ch);

            let mut reply = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), client_ch.read_to_end(&mut reply)).await.unwrap().unwrap();
            assert_eq!(reply, expected);
            client_driver.abort();
            server_driver.abort();
        });
    }
}
