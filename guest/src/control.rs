//! Concurrent agent sockets over a private, flow-controlled virtio-serial link.
//!
//! Shared by the host and guest. Socket pairs preserve the agent's existing
//! deadlines, half-close and attachment cancellation semantics. A single
//! synchronous `poll(2)` loop multiplexes bounded binary frames with per-stream
//! credit flow control so a stalled stream never blocks other requests.
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const STREAMS: usize = 64;
const HEADER_LEN: usize = 9;
const MAX_FRAME_LEN: usize = 16 * 1024;
const INITIAL_WINDOW: u32 = 256 * 1024;
const WINDOW_UPDATE_THRESHOLD: u32 = INITIAL_WINDOW / 2;
const TX_BUF_LIMIT: usize = 256 * 1024;
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(5);
const GOAWAY_TIMEOUT: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF: Duration = Duration::from_millis(10);

const FRAME_OPEN: u8 = 1;
const FRAME_ACK: u8 = 2;
const FRAME_DATA: u8 = 3;
const FRAME_FIN: u8 = 4;
const FRAME_RST: u8 = 5;
const FRAME_WINDOW: u8 = 6;
const FRAME_GOAWAY: u8 = 7;

pub const PORT_NAME: &str = "org.flexvm.control";

type Reply = SyncSender<io::Result<UnixStream>>;

struct Open {
    reply: Reply,
    deadline: Instant,
}

pub struct Client {
    requests: SyncSender<Open>,
    stop: Arc<AtomicBool>,
    wake: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

pub struct IncomingRequest {
    peer: UnixStream,
    payload: Receiver<()>,
}

impl IncomingRequest {
    /// Keep dispatch order while the bridge negotiates the stream. The guest's
    /// request-line timeout starts only after a request byte reaches the socket.
    pub fn wait_for_payload(self) -> Option<UnixStream> {
        self.payload.recv().ok().map(|()| self.peer)
    }
}

fn wake_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn signal_wake(fd: RawFd) {
    let byte = [1u8];
    loop {
        let n = unsafe { libc::write(fd, byte.as_ptr().cast(), 1) };
        if n >= 0 {
            return;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return;
        }
    }
}

fn drain_wake(fd: RawFd) {
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            continue;
        }
        if n == 0 {
            return;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return;
        }
    }
}

impl Client {
    pub fn connect(io: UnixStream) -> io::Result<Self> {
        io.set_nonblocking(true)?;
        let (wake_rx, wake_tx) = wake_pipe()?;
        let (requests, incoming) = mpsc::sync_channel(STREAMS);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::Builder::new().name("serial-control".into()).spawn(move || {
            let mut mux = Mux::new(Transport::Unix(io), Side::Client, Some(incoming), None, Some(stopped), Some(wake_rx));
            let _ = mux.run();
        })?;
        Ok(Self { requests, stop, wake: wake_tx, thread: Some(thread) })
    }

    pub fn open(&self, deadline: Instant) -> io::Result<UnixStream> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let (reply, answer) = mpsc::sync_channel(1);
        self.requests.try_send(Open { reply, deadline }).map_err(|e| match e {
            TrySendError::Full(_) => io::Error::new(io::ErrorKind::WouldBlock, "serial control request queue is full"),
            TrySendError::Disconnected(_) => io::Error::new(io::ErrorKind::BrokenPipe, "serial control disconnected"),
        })?;
        signal_wake(self.wake.as_raw_fd());
        answer.recv_timeout(left).map_err(|e| match e {
            mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
            mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe,
        })?
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        signal_wake(self.wake.as_raw_fd());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn serve(port: File, incoming: SyncSender<IncomingRequest>) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(port.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(port.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut mux = Mux::new(Transport::Serial(Serial::new(port)), Side::Agent, None, Some(incoming), None, None);
    mux.run()
}

pub(crate) fn hung_up(fd: RawFd) -> io::Result<bool> {
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

fn poll_fds(fds: &mut [libc::pollfd], timeout_ms: i32) -> io::Result<usize> {
    loop {
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

enum ReadOutcome {
    Data(usize),
    Eof,
    WouldBlock,
    WaitReconnect,
}

enum WriteOutcome {
    Wrote(usize),
    WouldBlock,
    WaitReconnect,
}

/// Virtio RX can arrive before the deferred host-open control message. Confirm
/// the live peer through current poll state or successful TX before treating EOF
/// as the end of a connection; received bytes alone are insufficient.
struct Serial {
    file: File,
    connected: bool,
}

impl Serial {
    fn new(file: File) -> Self {
        Self { file, connected: false }
    }

    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    fn confirm_connection(&mut self) -> io::Result<()> {
        if !self.connected && !hung_up(self.file.as_raw_fd())? {
            self.connected = true;
        }
        Ok(())
    }

    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<ReadOutcome> {
        self.confirm_connection()?;
        loop {
            match self.file.read(buf) {
                Ok(0) if !self.connected => return Ok(ReadOutcome::WaitReconnect),
                Ok(0) => return Ok(ReadOutcome::Eof),
                Ok(n) => return Ok(ReadOutcome::Data(n)),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if !self.connected && hung_up(self.file.as_raw_fd())? {
                        return Ok(ReadOutcome::WaitReconnect);
                    }
                    return Ok(ReadOutcome::WouldBlock);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn try_write(&mut self, buf: &[u8]) -> io::Result<WriteOutcome> {
        self.confirm_connection()?;
        loop {
            match self.file.write(buf) {
                Ok(n) => {
                    self.connected |= n != 0;
                    return Ok(WriteOutcome::Wrote(n));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // A disconnected virtio port reports HUP while writes
                    // return EAGAIN. End an established parser so it can reset.
                    if self.connected && hung_up(self.file.as_raw_fd())? {
                        return Err(io::ErrorKind::BrokenPipe.into());
                    }
                    if !self.connected && hung_up(self.file.as_raw_fd())? {
                        return Ok(WriteOutcome::WaitReconnect);
                    }
                    return Ok(WriteOutcome::WouldBlock);
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[cfg(test)]
    fn read_timeout(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.try_read(buf)? {
                ReadOutcome::Data(n) => return Ok(Some(n)),
                ReadOutcome::Eof => return Ok(Some(0)),
                ReadOutcome::WaitReconnect => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Ok(None);
                    }
                    std::thread::sleep(left.min(RECONNECT_BACKOFF));
                }
                ReadOutcome::WouldBlock => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Ok(None);
                    }
                    let ms = left.as_millis().min(i32::MAX as u128).max(1) as i32;
                    let mut pfd = [libc::pollfd { fd: self.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
                    poll_fds(&mut pfd, ms)?;
                }
            }
        }
    }
}

enum Transport {
    Unix(UnixStream),
    Serial(Serial),
}

impl Transport {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Unix(s) => s.as_raw_fd(),
            Self::Serial(s) => s.as_raw_fd(),
        }
    }

    fn try_read(&mut self, buf: &mut [u8]) -> io::Result<ReadOutcome> {
        match self {
            Self::Unix(s) => loop {
                match s.read(buf) {
                    Ok(0) => return Ok(ReadOutcome::Eof),
                    Ok(n) => return Ok(ReadOutcome::Data(n)),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(ReadOutcome::WouldBlock),
                    Err(e) => return Err(e),
                }
            },
            Self::Serial(s) => s.try_read(buf),
        }
    }

    fn try_write(&mut self, buf: &[u8]) -> io::Result<WriteOutcome> {
        match self {
            Self::Unix(s) => loop {
                match s.write(buf) {
                    Ok(n) => return Ok(WriteOutcome::Wrote(n)),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(WriteOutcome::WouldBlock),
                    Err(e) => return Err(e),
                }
            },
            Self::Serial(s) => s.try_write(buf),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Client,
    Agent,
}

struct ActiveStream {
    local: UnixStream,
    to_local: VecDeque<u8>,
    send_window: u32,
    recv_window: u32,
    recv_consumed: u32,
    local_read_eof: bool,
    local_hup: bool,
    local_write_shutdown: bool,
    remote_fin: bool,
    remote_rst: bool,
    ready: Option<mpsc::Sender<()>>,
    first_byte_deadline: Option<Instant>,
}

impl ActiveStream {
    fn new(local: UnixStream, ready: Option<mpsc::Sender<()>>, first_byte_deadline: Option<Instant>) -> Self {
        Self {
            local,
            to_local: VecDeque::new(),
            send_window: INITIAL_WINDOW,
            recv_window: INITIAL_WINDOW,
            recv_consumed: 0,
            local_read_eof: false,
            local_hup: false,
            local_write_shutdown: false,
            remote_fin: false,
            remote_rst: false,
            ready,
            first_byte_deadline,
        }
    }
}

enum StreamEntry {
    Opening { reply: Reply, deadline: Instant },
    Open(ActiveStream),
}

struct Mux {
    transport: Transport,
    side: Side,
    requests: Option<Receiver<Open>>,
    incoming: Option<SyncSender<IncomingRequest>>,
    stop: Option<Arc<AtomicBool>>,
    wake: Option<OwnedFd>,
    pending_opens: VecDeque<Open>,
    streams: BTreeMap<u32, StreamEntry>,
    next_stream_id: u32,
    rr_cursor: u32,
    rx_buf: Vec<u8>,
    rx_pos: usize,
    tx_buf: VecDeque<u8>,
    serial_backoff_until: Option<Instant>,
}

impl Mux {
    fn new(
        transport: Transport,
        side: Side,
        requests: Option<Receiver<Open>>,
        incoming: Option<SyncSender<IncomingRequest>>,
        stop: Option<Arc<AtomicBool>>,
        wake: Option<OwnedFd>,
    ) -> Self {
        Self {
            transport,
            side,
            requests,
            incoming,
            stop,
            wake,
            pending_opens: VecDeque::new(),
            streams: BTreeMap::new(),
            next_stream_id: 1,
            rr_cursor: 0,
            rx_buf: Vec::with_capacity(32 * 1024),
            rx_pos: 0,
            tx_buf: VecDeque::with_capacity(32 * 1024),
            serial_backoff_until: None,
        }
    }

    fn queue_frame(&mut self, kind: u8, stream_id: u32, len: u32, payload: &[u8]) {
        let mut header = [0u8; HEADER_LEN];
        header[0] = kind;
        header[1..5].copy_from_slice(&stream_id.to_le_bytes());
        header[5..9].copy_from_slice(&len.to_le_bytes());
        self.tx_buf.extend(header);
        self.tx_buf.extend(payload);
    }

    fn alloc_stream_id(&mut self) -> u32 {
        loop {
            let id = self.next_stream_id;
            self.next_stream_id = self.next_stream_id.wrapping_add(1);
            if self.next_stream_id == 0 {
                self.next_stream_id = 1;
            }
            if !self.streams.contains_key(&id) {
                return id;
            }
        }
    }

    fn in_serial_backoff(&mut self, now: Instant) -> bool {
        if let Some(until) = self.serial_backoff_until {
            if now < until {
                return true;
            }
            self.serial_backoff_until = None;
        }
        false
    }

    fn drain_requests(&mut self) -> bool {
        let Some(requests) = &self.requests else {
            return true;
        };
        loop {
            match requests.try_recv() {
                Ok(open) => self.pending_opens.push_back(open),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return false,
            }
        }
        let now = Instant::now();
        while let Some(front) = self.pending_opens.front() {
            if now >= front.deadline {
                let expired = self.pending_opens.pop_front().unwrap();
                let _ = expired.reply.send(Err(io::ErrorKind::TimedOut.into()));
                continue;
            }
            if self.streams.len() >= STREAMS {
                break;
            }
            let open = self.pending_opens.pop_front().unwrap();
            let id = self.alloc_stream_id();
            self.streams.insert(id, StreamEntry::Opening { reply: open.reply, deadline: open.deadline });
            self.queue_frame(FRAME_OPEN, id, 0, &[]);
        }
        true
    }

    fn check_deadlines(&mut self, now: Instant) {
        let mut expired_opens = Vec::new();
        let mut expired_first_byte = Vec::new();
        for (&id, entry) in &self.streams {
            match entry {
                StreamEntry::Opening { deadline, .. } if now >= *deadline => expired_opens.push(id),
                StreamEntry::Open(s) if s.first_byte_deadline.is_some_and(|d| now >= d) => expired_first_byte.push(id),
                _ => {}
            }
        }
        for id in expired_opens {
            if let Some(StreamEntry::Opening { reply, .. }) = self.streams.remove(&id) {
                let _ = reply.send(Err(io::ErrorKind::TimedOut.into()));
                self.queue_frame(FRAME_RST, id, 0, &[]);
            }
        }
        for id in expired_first_byte {
            self.streams.remove(&id);
            self.queue_frame(FRAME_RST, id, 0, &[]);
        }
        while self.pending_opens.front().is_some_and(|o| now >= o.deadline) {
            let expired = self.pending_opens.pop_front().unwrap();
            let _ = expired.reply.send(Err(io::ErrorKind::TimedOut.into()));
        }
        while self.streams.len() < STREAMS {
            let Some(open) = self.pending_opens.pop_front() else {
                break;
            };
            if now >= open.deadline {
                let _ = open.reply.send(Err(io::ErrorKind::TimedOut.into()));
                continue;
            }
            let id = self.alloc_stream_id();
            self.streams.insert(id, StreamEntry::Opening { reply: open.reply, deadline: open.deadline });
            self.queue_frame(FRAME_OPEN, id, 0, &[]);
        }
    }

    fn next_timeout_ms(&self, now: Instant) -> i32 {
        let mut earliest: Option<Instant> = self.serial_backoff_until;
        let mut consider = |t: Instant| {
            earliest = Some(match earliest {
                Some(cur) => cur.min(t),
                None => t,
            });
        };
        if let Some(front) = self.pending_opens.front() {
            consider(front.deadline);
        }
        for entry in self.streams.values() {
            match entry {
                StreamEntry::Opening { deadline, .. } => consider(*deadline),
                StreamEntry::Open(s) => {
                    if let Some(d) = s.first_byte_deadline {
                        consider(d);
                    }
                }
            }
        }
        match earliest {
            None => -1,
            Some(t) => {
                let dur = t.saturating_duration_since(now);
                if dur.is_zero() {
                    0
                } else {
                    dur.as_millis().min(i32::MAX as u128).max(1) as i32
                }
            }
        }
    }

    fn flush_transport(&mut self) -> io::Result<()> {
        while !self.tx_buf.is_empty() {
            let (front, _) = self.tx_buf.as_slices();
            match self.transport.try_write(front)? {
                WriteOutcome::Wrote(0) => return Err(io::ErrorKind::WriteZero.into()),
                WriteOutcome::Wrote(n) => {
                    self.tx_buf.drain(..n);
                }
                WriteOutcome::WouldBlock => break,
                WriteOutcome::WaitReconnect => {
                    self.serial_backoff_until = Some(Instant::now() + RECONNECT_BACKOFF);
                    break;
                }
            }
        }
        Ok(())
    }

    fn flush_goaway(&mut self) {
        // A device disconnect is not reliably surfaced as EOF by every
        // virtio-serial implementation. Explicitly terminate the old
        // parser on the wire before closing the host character device.
        self.queue_frame(FRAME_GOAWAY, 0, 0, &[]);
        let deadline = Instant::now() + GOAWAY_TIMEOUT;
        while !self.tx_buf.is_empty() {
            match self.flush_transport() {
                Ok(()) if self.tx_buf.is_empty() => break,
                Ok(()) => {}
                Err(_) => break,
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let ms = left.as_millis().min(i32::MAX as u128).max(1) as i32;
            let mut pfd = [libc::pollfd { fd: self.transport.as_raw_fd(), events: libc::POLLOUT, revents: 0 }];
            if poll_fds(&mut pfd, ms).is_err() {
                break;
            }
            if pfd[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                break;
            }
        }
    }

    fn try_write_local(&mut self, id: u32) {
        let mut window_update = 0u32;
        let mut remove = false;
        let mut send_rst = false;
        if let Some(StreamEntry::Open(stream)) = self.streams.get_mut(&id) {
            while !stream.to_local.is_empty() {
                let (front, _) = stream.to_local.as_slices();
                match stream.local.write(front) {
                    Ok(0) => {
                        if self.side == Side::Client {
                            send_rst = true;
                            remove = true;
                        } else {
                            stream.to_local.clear();
                            stream.local_write_shutdown = true;
                        }
                        break;
                    }
                    Ok(n) => {
                        stream.to_local.drain(..n);
                        stream.recv_consumed = stream.recv_consumed.saturating_add(n as u32);
                        if let Some(ready) = stream.ready.take() {
                            stream.first_byte_deadline = None;
                            let _ = ready.send(());
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        if self.side == Side::Client {
                            send_rst = true;
                            remove = true;
                        } else {
                            stream.to_local.clear();
                            stream.local_write_shutdown = true;
                        }
                        break;
                    }
                }
            }
            if !remove {
                if stream.recv_consumed >= WINDOW_UPDATE_THRESHOLD && !stream.remote_fin && !stream.remote_rst {
                    window_update = stream.recv_consumed;
                    stream.recv_window = stream.recv_window.saturating_add(window_update);
                    stream.recv_consumed = 0;
                }
                if stream.to_local.is_empty() {
                    if stream.remote_rst {
                        remove = true;
                    } else if stream.remote_fin {
                        if !stream.local_write_shutdown {
                            let _ = stream.local.shutdown(Shutdown::Write);
                            stream.local_write_shutdown = true;
                        }
                        if stream.local_read_eof {
                            remove = true;
                        }
                    }
                }
            }
        }
        if window_update > 0 {
            self.queue_frame(FRAME_WINDOW, id, window_update, &[]);
        }
        if remove {
            self.streams.remove(&id);
            if send_rst {
                self.queue_frame(FRAME_RST, id, 0, &[]);
            }
        }
    }

    fn read_local_once(&mut self, id: u32, scratch: &mut [u8; MAX_FRAME_LEN]) -> bool {
        let mut data_len = 0usize;
        let mut hit_eof = false;
        let mut hit_err = false;
        let mut local_hup = false;
        if let Some(StreamEntry::Open(stream)) = self.streams.get_mut(&id) {
            if stream.local_read_eof || stream.send_window == 0 || self.tx_buf.len() >= TX_BUF_LIMIT {
                return false;
            }
            let max_read = (stream.send_window as usize).min(MAX_FRAME_LEN);
            loop {
                match stream.local.read(&mut scratch[..max_read]) {
                    Ok(0) => {
                        stream.local_read_eof = true;
                        hit_eof = true;
                        local_hup = stream.local_hup || hung_up(stream.local.as_raw_fd()).unwrap_or(true);
                        break;
                    }
                    Ok(n) => {
                        stream.send_window -= n as u32;
                        data_len = n;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return false,
                    Err(_) => {
                        hit_err = true;
                        break;
                    }
                }
            }
        } else {
            return false;
        }
        if data_len > 0 {
            self.queue_frame(FRAME_DATA, id, data_len as u32, &scratch[..data_len]);
            return true;
        }
        if hit_err {
            self.streams.remove(&id);
            self.queue_frame(FRAME_RST, id, 0, &[]);
            return false;
        }
        if hit_eof {
            if self.side == Side::Client && local_hup {
                self.streams.remove(&id);
                self.queue_frame(FRAME_RST, id, 0, &[]);
            } else {
                self.queue_frame(FRAME_FIN, id, 0, &[]);
                if self.side == Side::Agent && local_hup {
                    self.streams.remove(&id);
                    self.queue_frame(FRAME_RST, id, 0, &[]);
                } else if let Some(StreamEntry::Open(s)) = self.streams.get(&id) {
                    if s.remote_fin && s.to_local.is_empty() {
                        self.streams.remove(&id);
                    }
                }
            }
        }
        false
    }

    fn drain_hup_agent_streams(&mut self, scratch: &mut [u8; MAX_FRAME_LEN]) {
        if self.side != Side::Agent {
            return;
        }
        let ids: Vec<u32> = self
            .streams
            .iter()
            .filter_map(|(&id, entry)| match entry {
                StreamEntry::Open(s) if s.local_hup && !s.local_read_eof && s.send_window > 0 => Some(id),
                _ => None,
            })
            .collect();
        for id in ids {
            while self.tx_buf.len() < TX_BUF_LIMIT && self.read_local_once(id, scratch) {}
        }
    }

    fn read_transport(&mut self) -> io::Result<bool> {
        let mut scratch = [0u8; 32 * 1024];
        loop {
            match self.transport.try_read(&mut scratch)? {
                ReadOutcome::Data(n) => {
                    self.rx_buf.extend_from_slice(&scratch[..n]);
                    if !self.dispatch_frames()? {
                        return Ok(false);
                    }
                }
                ReadOutcome::Eof => return Ok(false),
                ReadOutcome::WouldBlock => return Ok(true),
                ReadOutcome::WaitReconnect => {
                    self.serial_backoff_until = Some(Instant::now() + RECONNECT_BACKOFF);
                    return Ok(true);
                }
            }
        }
    }

    fn dispatch_frames(&mut self) -> io::Result<bool> {
        loop {
            let avail = self.rx_buf.len() - self.rx_pos;
            if avail < HEADER_LEN {
                break;
            }
            let h = &self.rx_buf[self.rx_pos..self.rx_pos + HEADER_LEN];
            let kind = h[0];
            let stream_id = u32::from_le_bytes([h[1], h[2], h[3], h[4]]);
            let len = u32::from_le_bytes([h[5], h[6], h[7], h[8]]);
            let payload_len = match kind {
                FRAME_DATA => {
                    if len == 0 || len as usize > MAX_FRAME_LEN {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid control data frame length"));
                    }
                    len as usize
                }
                FRAME_OPEN | FRAME_ACK | FRAME_FIN | FRAME_RST | FRAME_GOAWAY => {
                    if len != 0 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected control frame payload"));
                    }
                    0
                }
                FRAME_WINDOW => {
                    if len == 0 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "zero control window update"));
                    }
                    0
                }
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown control frame kind")),
            };
            if avail < HEADER_LEN + payload_len {
                break;
            }
            let payload_start = self.rx_pos + HEADER_LEN;
            self.rx_pos = payload_start + payload_len;
            match kind {
                FRAME_GOAWAY => return Ok(false),
                FRAME_OPEN => self.handle_open(stream_id)?,
                FRAME_ACK => self.handle_ack(stream_id),
                FRAME_DATA => {
                    let payload = self.rx_buf[payload_start..payload_start + payload_len].to_vec();
                    self.handle_data(stream_id, &payload)?;
                }
                FRAME_FIN => self.handle_fin(stream_id),
                FRAME_RST => self.handle_rst(stream_id),
                FRAME_WINDOW => self.handle_window(stream_id, len)?,
                _ => unreachable!(),
            }
        }
        if self.rx_pos == self.rx_buf.len() {
            self.rx_buf.clear();
            self.rx_pos = 0;
        } else if self.rx_pos >= 16 * 1024 {
            self.rx_buf.drain(..self.rx_pos);
            self.rx_pos = 0;
        }
        Ok(true)
    }

    fn handle_open(&mut self, id: u32) -> io::Result<()> {
        let Some(incoming) = &self.incoming else {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "guest opened an unsolicited control stream"));
        };
        if id == 0 || self.streams.len() >= STREAMS || self.streams.contains_key(&id) {
            self.queue_frame(FRAME_RST, id, 0, &[]);
            return Ok(());
        }
        let (peer, local) = match UnixStream::pair().and_then(|(p, l)| {
            l.set_nonblocking(true)?;
            Ok((p, l))
        }) {
            Ok(pair) => pair,
            Err(_) => {
                self.queue_frame(FRAME_RST, id, 0, &[]);
                return Ok(());
            }
        };
        let (ready, payload) = mpsc::channel();
        if incoming.try_send(IncomingRequest { peer, payload }).is_err() {
            self.queue_frame(FRAME_RST, id, 0, &[]);
            return Ok(());
        }
        let active = ActiveStream::new(local, Some(ready), Some(Instant::now() + FIRST_BYTE_TIMEOUT));
        self.streams.insert(id, StreamEntry::Open(active));
        self.queue_frame(FRAME_ACK, id, 0, &[]);
        Ok(())
    }

    fn handle_ack(&mut self, id: u32) {
        let Some(entry) = self.streams.remove(&id) else {
            self.queue_frame(FRAME_RST, id, 0, &[]);
            return;
        };
        let StreamEntry::Opening { reply, .. } = entry else {
            self.streams.insert(id, entry);
            return;
        };
        let pair = UnixStream::pair().and_then(|(peer, local)| {
            local.set_nonblocking(true)?;
            Ok((peer, local))
        });
        match pair {
            Ok((peer, local)) => {
                if reply.send(Ok(peer)).is_ok() {
                    self.streams.insert(id, StreamEntry::Open(ActiveStream::new(local, None, None)));
                } else {
                    self.queue_frame(FRAME_RST, id, 0, &[]);
                }
            }
            Err(e) => {
                let _ = reply.send(Err(e));
                self.queue_frame(FRAME_RST, id, 0, &[]);
            }
        }
    }

    fn handle_data(&mut self, id: u32, payload: &[u8]) -> io::Result<()> {
        let Some(StreamEntry::Open(stream)) = self.streams.get_mut(&id) else {
            return Ok(());
        };
        if stream.remote_fin {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "control data after EOF"));
        }
        if payload.len() > stream.recv_window as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "control stream window exceeded"));
        }
        stream.recv_window -= payload.len() as u32;
        stream.to_local.extend(payload);
        self.try_write_local(id);
        Ok(())
    }

    fn handle_fin(&mut self, id: u32) {
        if let Some(StreamEntry::Open(stream)) = self.streams.get_mut(&id) {
            stream.remote_fin = true;
            if stream.to_local.is_empty() {
                if !stream.local_write_shutdown {
                    let _ = stream.local.shutdown(Shutdown::Write);
                    stream.local_write_shutdown = true;
                }
                if stream.local_read_eof {
                    self.streams.remove(&id);
                }
            }
        }
    }

    fn handle_rst(&mut self, id: u32) {
        match self.streams.get_mut(&id) {
            Some(StreamEntry::Opening { .. }) => {
                if let Some(StreamEntry::Opening { reply, .. }) = self.streams.remove(&id) {
                    let _ = reply.send(Err(io::ErrorKind::UnexpectedEof.into()));
                }
            }
            Some(StreamEntry::Open(stream)) => {
                if self.side == Side::Agent || stream.to_local.is_empty() {
                    self.streams.remove(&id);
                } else {
                    stream.remote_rst = true;
                }
            }
            None => {}
        }
    }

    fn handle_window(&mut self, id: u32, delta: u32) -> io::Result<()> {
        if let Some(StreamEntry::Open(stream)) = self.streams.get_mut(&id) {
            stream.send_window = stream.send_window.checked_add(delta).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "control window overflow"))?;
        }
        Ok(())
    }

    fn run(&mut self) -> io::Result<()> {
        let mut pollfds = Vec::with_capacity(STREAMS + 2);
        let mut polled_streams = Vec::with_capacity(STREAMS);
        let mut read_scratch = [0u8; MAX_FRAME_LEN];
        loop {
            if self.stop.as_ref().is_some_and(|s| s.load(Ordering::Acquire)) {
                self.flush_goaway();
                return Ok(());
            }
            if !self.drain_requests() {
                self.flush_goaway();
                return Ok(());
            }
            let now = Instant::now();
            self.check_deadlines(now);
            let backoff = self.in_serial_backoff(now);
            if !backoff && !self.tx_buf.is_empty() {
                self.flush_transport()?;
            }
            self.drain_hup_agent_streams(&mut read_scratch);
            let backoff = self.in_serial_backoff(Instant::now());
            if !backoff && !self.tx_buf.is_empty() {
                self.flush_transport()?;
            }

            pollfds.clear();
            polled_streams.clear();
            let wake_idx = if let Some(wake) = &self.wake {
                let idx = pollfds.len();
                pollfds.push(libc::pollfd { fd: wake.as_raw_fd(), events: libc::POLLIN, revents: 0 });
                Some(idx)
            } else {
                None
            };
            let transport_idx = if !backoff {
                let idx = pollfds.len();
                let mut events = libc::POLLIN;
                if !self.tx_buf.is_empty() {
                    events |= libc::POLLOUT;
                }
                pollfds.push(libc::pollfd { fd: self.transport.as_raw_fd(), events, revents: 0 });
                Some(idx)
            } else {
                None
            };
            let can_read_local = self.tx_buf.len() < TX_BUF_LIMIT;
            for (&id, entry) in &self.streams {
                let StreamEntry::Open(stream) = entry else {
                    continue;
                };
                if self.side == Side::Agent && stream.local_hup && !stream.local_read_eof {
                    continue;
                }
                let mut events = 0i16;
                if can_read_local && !stream.local_read_eof && stream.send_window > 0 {
                    events |= libc::POLLIN;
                }
                if !stream.to_local.is_empty() {
                    events |= libc::POLLOUT;
                }
                polled_streams.push((id, pollfds.len()));
                pollfds.push(libc::pollfd { fd: stream.local.as_raw_fd(), events, revents: 0 });
            }

            let timeout_ms = self.next_timeout_ms(Instant::now());
            poll_fds(&mut pollfds, timeout_ms)?;

            if let Some(idx) = wake_idx {
                if pollfds[idx].revents & libc::POLLIN != 0 {
                    if let Some(wake) = &self.wake {
                        drain_wake(wake.as_raw_fd());
                    }
                }
            }

            if let Some(idx) = transport_idx {
                let revents = pollfds[idx].revents;
                if revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 && !self.read_transport()? {
                    return Ok(());
                }
                if revents & libc::POLLOUT != 0 && !self.tx_buf.is_empty() {
                    self.flush_transport()?;
                }
            }

            // Round-robin stream handling so one busy stream cannot starve others.
            let split = polled_streams.partition_point(|&(id, _)| id <= self.rr_cursor);
            let mut last_read = None;
            for &(id, idx) in polled_streams[split..].iter().chain(&polled_streams[..split]) {
                let revents = pollfds[idx].revents;
                if revents == 0 {
                    continue;
                }
                if revents & libc::POLLOUT != 0 {
                    self.try_write_local(id);
                }
                if revents & libc::POLLIN != 0 && self.tx_buf.len() < TX_BUF_LIMIT && self.read_local_once(id, &mut read_scratch) {
                    last_read = Some(id);
                }
                if revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                    match self.side {
                        Side::Client => {
                            if self.streams.remove(&id).is_some() {
                                self.queue_frame(FRAME_RST, id, 0, &[]);
                            }
                        }
                        Side::Agent => {
                            let done = if let Some(StreamEntry::Open(s)) = self.streams.get_mut(&id) {
                                s.local_hup = true;
                                s.local_read_eof
                            } else {
                                false
                            };
                            if done {
                                self.streams.remove(&id);
                                self.queue_frame(FRAME_RST, id, 0, &[]);
                            }
                        }
                    }
                }
            }
            if let Some(id) = last_read {
                self.rr_cursor = id;
            }
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
        let mut writer = fifo.writer();
        let writing = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            writer.write_all(b"x")?;
            Ok::<_, io::Error>(writer)
        });
        let mut serial = Serial::new(reader);
        let mut bytes = [0];
        fn cpu_time() -> u64 {
            let mut time = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) }, 0);
            time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
        }
        let before = cpu_time();
        let result = serial.read_timeout(&mut bytes, Duration::from_millis(30)).unwrap();
        let cpu_ns = cpu_time() - before;
        let writer = writing.join().unwrap().unwrap();
        assert!(cpu_ns < 10_000_000, "idle serial read burned {cpu_ns} ns of thread CPU in a 30 ms wait");
        match result {
            None => assert_eq!(serial.read_timeout(&mut bytes, Duration::from_secs(3)).unwrap(), Some(1)),
            Some(read) => assert_eq!(read, 1),
        }
        assert_eq!(&bytes, b"x");
        drop(writer);
        assert_eq!(serial.read_timeout(&mut bytes, Duration::from_secs(3)).unwrap(), Some(0));
    }

    #[test]
    fn buffered_rx_does_not_confirm_a_reconnected_peer() {
        let (fifo, reader) = Fifo::new();
        let mut first = fifo.writer();
        first.write_all(b"x").unwrap();
        drop(first);
        let mut serial = Serial::new(reader);
        let mut bytes = [0];
        assert_eq!(serial.read_timeout(&mut bytes, Duration::from_secs(3)).unwrap(), Some(1));
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
        let result = serial.read_timeout(&mut bytes, Duration::from_millis(30)).unwrap();
        let writer = writing.join().unwrap().unwrap();
        match result {
            None => assert_eq!(serial.read_timeout(&mut bytes, Duration::from_secs(3)).unwrap(), Some(1)),
            Some(read) => assert_eq!(read, 1, "buffered RX incorrectly turned pre-open EOF into disconnect"),
        }
        assert_eq!(&bytes, b"y");
        drop(writer);
        assert_eq!(serial.read_timeout(&mut bytes, Duration::from_secs(3)).unwrap(), Some(0));
    }

    #[test]
    fn client_shutdown_sends_goaway_before_device_disconnect() {
        let (host, mut device) = UnixStream::pair().unwrap();
        device.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let client = Client::connect(host).unwrap();
        drop(client);
        let mut header = [0; HEADER_LEN];
        device.read_exact(&mut header).unwrap();
        assert_eq!(header, [FRAME_GOAWAY, 0, 0, 0, 0, 0, 0, 0, 0]);
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
}
