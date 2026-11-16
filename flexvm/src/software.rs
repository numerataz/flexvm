//! Named software VM owner using the ordinary name lock and control wire protocol.
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::host::{Backend, Entry, Host, Ident, NameLock};
use crate::util::{By, Result};
use crate::{bail, guest, image, qemu, util, vmproc};

const MAX_CONTROL: usize = 64;
const MAX_SESSIONS: usize = 48;

/// Conservatively hold the entire fixed-RAM grant for this initial owner path.
/// Unlike an ordinary start grant it must not expire while RAM is still promised.
pub struct Reservation {
    host: Host,
    grant: u64,
    hold: Option<crate::host::Hold>,
}

impl Reservation {
    pub fn new(host: &Host, mib: u32, deadline: Instant) -> Result<Self> {
        let (grant, hold) = host.grant_start(u64::from(mib), crate::host::Floor::Reserve, true, Some(deadline))?;
        Ok(Self { host: host.clone(), grant, hold })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        drop(self.hold.take());
        self.host.refund_by(self.grant, Some(Instant::now() + Duration::from_secs(2)));
    }
}

struct Owner {
    machine: Arc<qemu::Machine>,
    processes: Arc<qemu::Processes>,
    name: NameLock,
    host: Host,
    entry: Mutex<Entry>,
    op: RwLock<()>,
    ended: AtomicBool,
    active: AtomicUsize,
    sessions: AtomicUsize,
    epoch: u64,
}

impl Owner {
    fn switch(&self, paused: bool) -> Result<Value> {
        let _op = self.op.write().unwrap();
        self.processes.alive()?;
        if self.ended.load(Ordering::SeqCst) {
            bail!("software VM is ending");
        }
        let state = if paused { "paused" } else { "running" };
        if self.entry.lock().unwrap().state != state {
            if let Err(e) = self.machine.switch(if paused { "stop" } else { "cont" }, Instant::now() + guest::TIMEOUT) {
                // An uncertain engine transition is never published as running.
                self.ended.store(true, Ordering::SeqCst);
                self.processes.stop();
                return Err(e);
            }
            self.entry.lock().unwrap().state = state.into();
        }
        let published = self.entry.lock().unwrap().clone();
        self.name.publish(&published)?;
        Ok(json!({"state":state,"name":self.name.name}))
    }

    fn exec(&self, req: &Value, client: &UnixStream, acknowledged: &mut bool) -> Result<()> {
        let _op = self.op.read().unwrap();
        self.processes.alive()?;
        if self.ended.load(Ordering::SeqCst) {
            bail!("software VM is ending");
        }
        if self.entry.lock().unwrap().state == "paused" {
            bail!("vm {} is paused{} once flexvm unpause resumes it", self.name.name, guest::TRY_AGAIN);
        }
        let id = req["session"].as_str().ok_or("missing session id")?;
        let offset = req["offset"].as_u64().unwrap_or(0);
        let deadline = Instant::now() + guest::TIMEOUT;
        let action = req["action"].as_str().unwrap_or("start");
        let action = if action == "start" && req["cmd"].is_object() { "argv" } else { action };
        let claim = vmproc::Claim::new(id);
        let mut stream = if action == "attach" {
            let line = guest::attach_line(id, offset, claim.n, self.epoch, guest::AttachForm::Epoch, false)?;
            self.machine.request(&line, deadline)?
        } else {
            let body = if matches!(action, "start" | "argv") { guest::command_body(&req["cmd"])? } else { String::new() };
            guest::session_on(action, id, offset, &body, |line| self.machine.request(line, deadline))?
        };
        if action == "close" {
            let reply = guest::read_frame(&mut By { s: &mut stream, at: deadline })?;
            if !matches!(reply, Some((guest::FRAME_MSG, ref body)) if body == b"closed") {
                bail!("session close failed: {reply:?}");
            }
            util::send_json(&mut &*client, &json!({"ok":true}))?;
            *acknowledged = true;
            return Ok(());
        }
        util::send_json(&mut &*client, &json!({"ok":true}))?;
        *acknowledged = true;
        drop(_op);
        let late = vmproc::relay_direct(stream, client, req["interactive"] == true, &claim, &|| self.ended.load(Ordering::SeqCst), &|| {
            self.sessions.load(Ordering::SeqCst) >= MAX_SESSIONS * 3 / 4
        })?;
        if let Some((end, code)) = late {
            // The guest may have stopped waiting for an acknowledgment while a
            // slow client drained output. RELEASE checks delivery/attachment state.
            let _ = self.machine.message(&format!("RELEASE {id} {end} {code}"), Instant::now() + guest::TIMEOUT);
        }
        Ok(())
    }

    fn control(&self, mut client: UnixStream) {
        struct Slot<'a>(&'a AtomicUsize);
        impl Drop for Slot<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let mut slot = Some(Slot(&self.active));
        let mut acknowledged = false;
        let result = (|| -> Result<Value> {
            let deadline = Instant::now() + guest::TIMEOUT;
            let (wire, fds) = util::recv_with_fds_by(&client, util::MAX_LINE as usize, deadline)?;
            if !fds.is_empty() {
                bail!("software owner does not accept descriptors for this operation");
            }
            let req: Value = serde_json::from_slice(&wire)?;
            match req["op"].as_str().unwrap_or("") {
                "exec" => {
                    let _session = if req["action"] == "close" {
                        None
                    } else {
                        if self.sessions.fetch_add(1, Ordering::SeqCst) >= MAX_SESSIONS {
                            self.sessions.fetch_sub(1, Ordering::SeqCst);
                            return Err(vmproc::Busy(format!("software VM sessions are busy{}", guest::TRY_AGAIN)).into());
                        }
                        Some(Slot(&self.sessions))
                    };
                    if req["action"] != "close" {
                        drop(slot.take());
                    }
                    self.exec(&req, &client, &mut acknowledged)?;
                    Ok(Value::Null)
                }
                "resume" => self.switch(false),
                "debug" if req["what"] == "status" => Ok(serde_json::to_value(&*self.entry.lock().unwrap())?),
                op => bail!("software VM operation {op:?} is not implemented"),
            }
        })();
        if acknowledged {
            if let Err(e) = result {
                crate::info!("software exec relay ended: {e}");
            }
            return;
        }
        let reply = match result {
            Ok(Value::Null) => return,
            Ok(value) => json!({"ok":true,"result":value}),
            Err(e) => json!({"ok":false,"busy":e.is::<vmproc::Busy>(),"error":e.to_string()}),
        };
        let _ = By { s: &mut client, at: Instant::now() + guest::TIMEOUT }.write_all(format!("{reply}\n").as_bytes());
    }
}

pub fn run(host: Host, name: NameLock, machine: qemu::Machine, processes: Arc<qemu::Processes>, config: &qemu::Config, meta: &image::ImageMeta) -> Result<i32> {
    let machine = Arc::new(machine);
    let epoch = u64::from_str_radix(&util::random_hex(8)?, 16)?;
    let generation = u64::from_str_radix(&util::random_hex(8)?, 16)?.max(1);
    let deadline = Instant::now() + guest::TIMEOUT;
    if machine.message(&format!("FENCE 1 {epoch}"), deadline)? != b"ok 1" {
        bail!("named software VM requires guest host-epoch fencing");
    }
    let (main_id, mut main_reader) = machine.start_exec(meta.argv.clone())?;
    machine.exec_started(&mut main_reader, &main_id)?;
    let entry = Entry {
        backend: Backend::QemuTcg {
            process: processes.engine_ident()?,
            image: meta.source.clone(),
            digest: meta.digest.clone(),
            argv: meta.argv.clone(),
            ram_mib: config.mem_mib,
        },
        name: name.name.clone(),
        ident: Ident::me(),
        ip: Some("169.254.1.2".parse()?),
        gen: generation,
        vcpus: config.vcpus,
        max_mib: u64::from(config.mem_mib),
        state: "running".into(),
        cmd: true,
        ..Default::default()
    };
    let socket = host.sock(&name.name)?;
    let private = crate::host::locks(socket.parent().ok_or("control socket has no directory")?).join(crate::socket::private_name());
    let listener = crate::socket::bind_private(&private, &socket)?;
    listener.set_nonblocking(true)?;
    let owner = Arc::new(Owner {
        machine,
        processes,
        name,
        host,
        entry: Mutex::new(entry),
        op: RwLock::new(()),
        ended: AtomicBool::new(false),
        active: AtomicUsize::new(0),
        sessions: AtomicUsize::new(0),
        epoch,
    });
    // The caller blocked these before starting its first worker/engine thread.
    let set = util::block_signals(&[libc::SIGTSTP, libc::SIGCONT, libc::SIGTERM]);
    let weak = Arc::downgrade(&owner);
    let signals = std::thread::Builder::new().name("software-signals".into()).spawn(move || {
        while let Some(owner) = weak.upgrade() {
            if owner.ended.load(Ordering::SeqCst) {
                break;
            }
            if let Some(sig) = util::take_signal(&set) {
                if sig == libc::SIGTERM {
                    crate::log!("software VM {}: suspend is not implemented; flexvm kill destroys it", owner.name.name);
                    continue;
                }
                if let Err(e) = owner.switch(sig == libc::SIGTSTP) {
                    crate::log!("software VM {}: {e}", owner.name.name);
                }
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    })?;
    let serving = owner.clone();
    let server = std::thread::Builder::new().name("software-owner".into()).spawn(move || {
        while !serving.ended.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut client, _)) => {
                    if serving.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONTROL {
                        serving.active.fetch_sub(1, Ordering::SeqCst);
                        let _ = By { s: &mut client, at: Instant::now() + Duration::from_millis(100) }
                            .write_all(b"{\"ok\":false,\"busy\":true,\"error\":\"software owner is busy\"}\n");
                        continue;
                    }
                    let request = serving.clone();
                    if std::thread::Builder::new().spawn(move || request.control(client)).is_err() {
                        serving.active.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    crate::log!("software owner listener failed: {e}");
                    serving.ended.store(true, Ordering::SeqCst);
                    serving.processes.stop();
                    break;
                }
            }
        }
    })?;
    let published = {
        let _op = owner.op.write().unwrap();
        let entry = owner.entry.lock().unwrap().clone();
        owner.name.publish(&entry)
    };
    let result = published.and_then(|()| {
        owner.machine.finish_exec(&mut main_reader, &main_id, |kind, bytes| {
            let mut output: Box<dyn Write> = if kind == guest::FRAME_STDERR { Box::new(std::io::stderr().lock()) } else { Box::new(std::io::stdout().lock()) };
            output.write_all(bytes)?;
            output.flush()?;
            Ok(())
        })
    });
    owner.ended.store(true, Ordering::SeqCst);
    {
        let _op = owner.op.write().unwrap();
        owner.entry.lock().unwrap().state = "ending".into();
        let entry = owner.entry.lock().unwrap().clone();
        let _ = owner.name.publish(&entry);
        owner.processes.stop();
    }
    let _ = signals.join();
    let _ = server.join();
    let entry = owner.entry.lock().unwrap().clone();
    let code =
        result.as_ref().copied().unwrap_or_else(|error| crate::template::interrupted_signal().map_or_else(|| vmproc::exit_code(error), |signal| 128 + signal));
    crate::containers::record_exit_of(
        &owner.host,
        &owner.name.name,
        &entry.ident,
        entry.ip.map(|ip| crate::Instance { ip, gen: entry.gen }),
        code,
        result.is_ok(),
    );
    result
}
