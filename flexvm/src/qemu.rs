//! Software execution with QEMU TCG and a userspace virtio-vsock backend.
//!
//! This cold-boot path owns both processes. Its state is separate from Firecracker
//! templates/checkpoints; native QEMU vhost-user-vsock is not yet migratable.
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::socket::{SocketRoot, Sockets};
use crate::util::{By, Result};
use crate::{bail, guest, template, util};

#[path = "../../guest/src/control.rs"]
#[allow(dead_code)]
mod control;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Vsock,
    Serial,
}

pub struct Config {
    pub control: Control,
    pub kernel: PathBuf,
    pub qemu: String,
    pub vsock_backend: String,
    pub mem_mib: u32,
    pub vcpus: u32,
    pub boot_timeout: Duration,
}

/// Children remain unreaped until their owner observes exit, so their pids cannot
/// be reused while cancellation holds this mutex.
#[derive(Default)]
pub struct Processes(Mutex<Vec<Process>>);

struct Process {
    child: Child,
    logging: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Process {
    fn drop(&mut self) {
        let exited = match self.child.try_wait() {
            Ok(status) => status.is_some(),
            Err(e) => e.raw_os_error() == Some(libc::ECHILD),
        };
        if !exited {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(logging) = self.logging.take() {
            let _ = logging.join();
        }
    }
}

impl Processes {
    pub fn stop(&self) {
        let mut children = self.0.lock().unwrap();
        while let Some(child) = children.pop() {
            drop(child);
        }
    }

    fn spawn(&self, cmd: &mut Command, log: &Path) -> Result<()> {
        template::interrupted()?;
        File::create(log)?;
        let (mut reader, writer) = std::io::pipe()?;
        cmd.stdin(Stdio::null()).stdout(writer.try_clone()?).stderr(writer);
        let parent = unsafe { libc::getpid() };
        // An abrupt owner exit also kills its engines; no shell/helper processes.
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // Job-control signals belong to the foreground owner. Its
                // engines are controlled through QMP and explicit cancellation.
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::other("software VM owner exited before spawn"));
                }
                Ok(())
            });
        }
        let mut children = self.0.lock().unwrap();
        // Cancellation may have arrived while opening logs/building the command.
        template::interrupted()?;
        let child = util::unblock_signals_in(cmd).spawn();
        // The command must not keep the pipe open after the engine exits.
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let mut process = Process { child: child?, logging: None };
        let log = log.to_path_buf();
        process.logging = Some(std::thread::Builder::new().spawn(move || {
            let mut buf = [0; 64 << 10];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        util::output::append_capped(&log, &buf[..n], util::output::LOG_CAP);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        })?);
        children.push(process);
        Ok(())
    }

    pub fn engine_ident(&self) -> Result<crate::host::Ident> {
        let children = self.0.lock().unwrap();
        let child = children.last().ok_or("software engine is not running")?;
        crate::host::Ident::of(child.child.id()).ok_or_else(|| "cannot identify software engine process".into())
    }

    pub fn alive(&self) -> Result<()> {
        template::interrupted()?;
        for process in self.0.lock().unwrap().iter_mut() {
            if let Some(status) = process.child.try_wait()? {
                bail!("software VM process {} exited: {status}", process.child.id());
            }
        }
        Ok(())
    }
}

pub struct Machine {
    processes: Arc<Processes>,
    sockets: Sockets,
    logs: PathBuf,
    control: Option<control::Client>,
}

/// A dead emulator must end an exec even if its device backend still holds the
/// stream open. Preserve partial frames while checking process death on idle I/O.
struct Watched<'a, R> {
    reader: R,
    processes: &'a Processes,
}

impl<R: Read> Read for Watched<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.reader.read(buf) {
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => {
                    self.processes.alive().map_err(|e| std::io::Error::other(e.to_string()))?;
                }
                result => return result,
            }
        }
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        self.processes.stop();
        self.control.take();
        let _ = fs::remove_dir_all(&self.logs);
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if !(128..=1_048_576).contains(&self.mem_mib) {
            bail!("software --mem must be 128..1048576 MiB");
        }
        if !(1..=256).contains(&self.vcpus) {
            bail!("software --vcpus must be 1..256");
        }
        if self.boot_timeout.is_zero() || self.boot_timeout > Duration::from_secs(3600) {
            bail!("software --timeout must be 1..3600 seconds (boot only)");
        }
        if !self.kernel.is_file() {
            bail!("software kernel is not a file: {}", self.kernel.display());
        }
        Ok(())
    }

    pub fn boot(&self, rootfs: &Path, processes: Arc<Processes>) -> Result<Machine> {
        self.validate()?;
        let rootfs = rootfs.canonicalize()?;
        let kernel = self.kernel.canonicalize()?;
        let key = PathBuf::from(format!("software-{}-{}", std::process::id(), util::random_hex(16)?));
        let root = SocketRoot::unique(&key)?;
        let sockets = root.allocate()?;
        let logs = root.dir.join("logs");
        fs::create_dir(&logs)?;
        let mut machine = Machine { processes, sockets, logs, control: None };
        let result = (|| -> Result<()> {
            let vhost = machine.sockets.uffd.clone();
            let deadline = Instant::now() + self.boot_timeout;
            if self.control == Control::Vsock {
                let mut backend = Command::new(&self.vsock_backend);
                backend.args(["--guest-cid", "3", "--socket"]).arg(&vhost).arg("--uds-path").arg(&machine.sockets.vsock);
                // Each VM owns a backend, and no sibling forwarding group is shared.
                backend.arg("--groups").arg(util::random_hex(16)?);
                machine.processes.spawn(&mut backend, &machine.logs.join("vsock.log"))?;
                while !vhost.exists() {
                    machine.processes.alive()?;
                    remaining(deadline)?;
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            let arch = std::env::consts::ARCH;
            let (board, cpu, console, block, vsock, nic) = match arch {
                // TCG implements AMD SVM: the ordinary guest Linux KVM driver
                // supplies the ABI without a host KVM device. Enforce support
                // instead of silently losing guest virtualization capabilities.
                "x86_64" => ("q35", "max,svm=on,npt=on,enforce=on", "ttyS0", "virtio-blk-pci", "vhost-user-vsock-pci", "virtio-net-pci"),
                "aarch64" => {
                    ("virt,virtualization=on,gic-version=3", "cortex-a72", "ttyAMA0", "virtio-blk-device", "vhost-user-vsock-device", "virtio-net-device")
                }
                _ => bail!("software execution is not implemented for {arch}"),
            };
            let mut cmd = Command::new(&self.qemu);
            cmd.args(["-machine", &format!("{board},memory-backend=ram"), "-accel", "tcg,thread=multi", "-cpu", cpu]);
            cmd.args(["-m", &self.mem_mib.to_string(), "-smp", &self.vcpus.to_string()]);
            cmd.args(["-object", &json!({"qom-type":"memory-backend-memfd", "id":"ram", "size":u64::from(self.mem_mib)<<20, "share":true}).to_string()]);
            cmd.args(["-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot"]);
            cmd.args(["-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]);
            let control_arg = if self.control == Control::Serial { " flexvm.control=serial" } else { "" };
            cmd.arg("-kernel").arg(&kernel).args([
                "-append",
                &format!("console={console} quiet panic=1 root=/dev/vda ro init=/sbin/flexvm-init flexvm.tmpfs_mib={}{}", self.mem_mib, control_arg),
            ]);
            cmd.args([
                "-blockdev",
                &json!({"driver":"raw", "node-name":"root", "read-only":true, "file":{"driver":"file", "filename":rootfs}}).to_string(),
                "-device",
                &format!("{block},drive=root"),
            ]);
            // Private short socket paths contain no keyval separators.
            if self.control == Control::Vsock {
                cmd.args(["-chardev", &format!("socket,id=vsock,path={}", vhost.display()), "-device", &format!("{vsock},chardev=vsock")]);
            } else {
                let device = if arch == "x86_64" { "virtio-serial-pci" } else { "virtio-serial-device" };
                cmd.args(["-device", &format!("{device},id=controlbus")]);
                cmd.args(["-chardev", &format!("socket,id=control,path={},server=on,wait=off", machine.sockets.vsock.display())]);
                cmd.args(["-device", &format!("virtserialport,bus=controlbus.0,chardev=control,name={}", control::PORT_NAME)]);
            }
            // Match the agent's existing static gateway and /32 configuration.
            cmd.args([
                "-netdev",
                "user,id=net,net=169.254.0.0/16,host=169.254.1.1,dns=169.254.1.3,dhcpstart=169.254.1.2,ipv6=off",
                "-device",
                &format!("{nic},netdev=net"),
            ]);
            cmd.args(["-qmp", &format!("unix:{},server=on,wait=off", machine.sockets.api.display())]);
            machine.processes.spawn(&mut cmd, &machine.logs.join("qemu.log"))?;
            crate::info!("software: waiting for guest agent");
            // The userspace device accepts host connections before the guest's
            // queues are initialized. Do not send requests into that boot window.
            loop {
                machine.processes.alive()?;
                remaining(deadline)?;
                let bytes = match fs::read(machine.logs.join("qemu.log")) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                    Err(e) => return Err(e.into()),
                };
                let marker = if self.control == Control::Serial { "flexvm-init: serial control ready" } else { "flexvm-init: ready" };
                if String::from_utf8_lossy(&bytes).contains(marker) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if self.control == Control::Serial {
                let stream = util::connect_unix(&machine.sockets.vsock, remaining(deadline)?)?;
                machine.control = Some(control::Client::connect(stream)?);
            }
            let mut last = String::new();
            loop {
                machine.processes.alive()?;
                if remaining(deadline).is_err() {
                    bail!("software VM boot timed out waiting for agent: {last}");
                }
                let attempt = (Instant::now() + guest::TIMEOUT).min(deadline);
                match machine.message("PING", attempt) {
                    Ok(m) if m == b"pong" => break,
                    Ok(m) => last = format!("unexpected PING reply: {}", String::from_utf8_lossy(&m)),
                    Err(e) => last = e.to_string(),
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let barrier = self.control == Control::Serial && machine.message("BARRIER 1 PROBE", deadline)? == b"ok BARRIER 1";
            if barrier && machine.message("BARRIER 1 QUIESCE 0 0 1", deadline)? != b"ok BARRIER 1 QUIESCED 0 1" {
                bail!("software guest did not quiesce request admission");
            }
            crate::info!("software: agent ready, checking pause/resume");
            // Verify actual machine pause/resume, not host SIGSTOP/SIGCONT.
            machine.switch("stop", deadline)?;
            machine.switch("cont", deadline)?;
            if barrier && machine.message("BARRIER 1 RESUME 0 0 0 1", deadline)? != b"ok BARRIER 1 RESUMED 0 1" {
                bail!("software guest did not resume request admission");
            }
            crate::info!("software: configuring guest network and clock");
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let line = format!("START 169.254.1.2 {}.{:09} 169.254.1.3", now.as_secs(), now.subsec_nanos());
            if machine.message(&line, deadline)? != b"ok" {
                bail!("software guest rejected network/clock setup");
            }
            crate::info!("software: guest ready");
            Ok(())
        })();
        if let Err(e) = result {
            return Err(format!("{e}\n{}", machine.diagnostics()).into());
        }
        Ok(machine)
    }
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        bail!("software VM boot timed out");
    }
    Ok(left)
}

fn check_engine(greeting: &Value, arch: &str) -> Result<()> {
    let version = &greeting["QMP"]["version"]["qemu"];
    let major = version["major"].as_u64();
    let minor = version["minor"].as_u64();
    if arch == "x86_64" && !matches!((major, minor), (Some(major), Some(minor)) if (major, minor) >= (9, 2)) {
        bail!("x86 software execution requires QEMU 9.2 or newer for correct SVM nested paging (found {version}); select a fixed engine with --qemu");
    }
    Ok(())
}

/// A single, deadline-bound QMP transaction stream. Descriptor-bearing commands
/// use the existing SCM_RIGHTS helper, including its partial-write handling.
struct Qmp {
    reader: BufReader<By<UnixStream>>,
    next_id: u64,
    broken: bool,
}

impl Qmp {
    fn connect(path: &Path, deadline: Instant) -> Result<Self> {
        let stream = util::connect_unix(path, remaining(deadline)?)?;
        let mut qmp = Self { reader: BufReader::new(By { s: stream, at: deadline }), next_id: 0, broken: false };
        let greeting = qmp.reply()?;
        if greeting["QMP"].is_null() {
            bail!("missing QMP greeting");
        }
        check_engine(&greeting, std::env::consts::ARCH)?;
        qmp.command("qmp_capabilities", json!({}), &[])?;
        Ok(qmp)
    }

    fn reply(&mut self) -> Result<Value> {
        loop {
            let mut line = String::new();
            if self.reader.by_ref().take(1 << 20).read_line(&mut line)? == 0 || !line.ends_with('\n') {
                bail!("QMP disconnected or reply too long");
            }
            let reply: Value = serde_json::from_str(&line)?;
            if reply["event"].is_null() {
                return Ok(reply);
            }
        }
    }

    fn command(&mut self, command: &str, arguments: Value, fds: &[RawFd]) -> Result<Value> {
        if self.broken {
            bail!("QMP connection is unusable after a protocol or I/O failure");
        }
        // A failed read can consume part of a frame. Reconnect after any
        // transport/protocol failure instead of reusing that ambiguous stream.
        self.broken = true;
        self.next_id = self.next_id.checked_add(1).ok_or("QMP request ID exhausted")?;
        let mut wire = serde_json::to_vec(&json!({"execute":command,"arguments":arguments,"id":self.next_id}))?;
        wire.push(b'\n');
        let stream = self.reader.get_ref();
        util::send_with_fds(&stream.s, &wire, fds, stream.at)?;
        let reply = self.reply()?;
        if reply["id"].is_null() && !reply["error"].is_null() {
            bail!("QMP protocol error while waiting for {command}: {}", reply["error"]);
        }
        if reply["id"].as_u64() != Some(self.next_id) {
            bail!("QMP response ID does not match {command}: {reply}");
        }
        if !reply["error"].is_null() {
            self.broken = false;
            bail!("QMP refused {command}: {}", reply["error"]);
        }
        let result = reply.get("return").cloned().ok_or_else(|| format!("QMP missing {command} result: {reply}"))?;
        self.broken = false;
        Ok(result)
    }
}

impl Machine {
    /// vhost-device-vsock 0.3 reads ahead and discards bytes after CONNECT.
    /// Wait for its OK before writing the agent command; Firecracker keeps its
    /// existing pipelined handshake and does not pay this extra round trip.
    pub fn request(&self, line: &str, deadline: Instant) -> Result<BufReader<std::os::unix::net::UnixStream>> {
        let stream = match &self.control {
            Some(control) => control.open(deadline)?,
            None => util::connect_unix(&self.sockets.vsock, remaining(deadline)?)?,
        };
        let mut r = BufReader::with_capacity(1, stream);
        if self.control.is_none() {
            By { s: r.get_mut(), at: deadline }.write_all(b"CONNECT 52\n")?;
            let mut ok = String::new();
            By { s: &mut r, at: deadline }.take(64).read_line(&mut ok)?;
            if !ok.starts_with("OK ") || !ok.ends_with('\n') {
                bail!("userspace vsock connect refused: {ok:?}");
            }
        }
        By { s: r.get_mut(), at: deadline }.write_all(format!("{line}\n").as_bytes())?;
        Ok(r)
    }

    pub fn message(&self, line: &str, deadline: Instant) -> Result<Vec<u8>> {
        let mut r = self.request(line, deadline)?;
        match guest::read_frame(&mut By { s: &mut r, at: deadline })? {
            Some((guest::FRAME_MSG, m)) => Ok(m),
            other => bail!("unexpected software guest reply: {other:?}"),
        }
    }

    pub fn switch(&self, command: &str, deadline: Instant) -> Result<()> {
        let mut qmp = Qmp::connect(&self.sockets.api, deadline)?;
        qmp.command(command, json!({}), &[])?;
        let state = qmp.command("query-status", json!({}), &[])?;
        let expected = if command == "stop" { "paused" } else { "running" };
        if state["status"] != expected {
            bail!("QMP did not enter {expected}: {state}");
        }
        Ok(())
    }

    pub fn start_exec(&self, argv: Vec<String>) -> Result<(String, BufReader<UnixStream>)> {
        let body = guest::Exec { argv, ..Default::default() }.encode()?;
        guest::fits(&body)?;
        let id = util::random_hex(16)?;
        let deadline = Instant::now() + guest::TIMEOUT;
        let reader = guest::session_on("argv", &id, 0, &body, |line| self.request(line, deadline))?;
        guest::untimed(&reader)?;
        reader.get_ref().set_read_timeout(Some(Duration::from_millis(250)))?;
        Ok((id, reader))
    }

    pub fn exec_started(&self, reader: &mut BufReader<UnixStream>, id: &str) -> Result<()> {
        match guest::read_frame(&mut Watched { reader, processes: &self.processes })? {
            Some((guest::FRAME_MSG, body)) if body == id.as_bytes() => Ok(()),
            other => bail!("software command was not accepted: {other:?}"),
        }
    }

    pub fn finish_exec(&self, reader: &mut BufReader<UnixStream>, id: &str, out: impl FnMut(u8, &[u8]) -> Result<()>) -> Result<i32> {
        guest::exec_output(&mut Watched { reader, processes: &self.processes }, id, out)
    }

    pub fn exec(&self, argv: Vec<String>, out: impl FnMut(u8, &[u8]) -> Result<()>) -> Result<i32> {
        let (id, mut reader) = self.start_exec(argv)?;
        self.finish_exec(&mut reader, &id, out)
    }

    fn diagnostics(&self) -> String {
        ["qemu.log", "vsock.log"]
            .iter()
            .map(|name| {
                let bytes = fs::read(self.logs.join(name)).unwrap_or_default();
                let start = bytes.len().saturating_sub(8192);
                format!("{name}: {}", String::from_utf8_lossy(&bytes[start..]))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn qmp_peer(listener: UnixListener) -> UnixStream {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        writeln!(stream, "{}", json!({"QMP":{"version":{"qemu":{"major":10,"minor":2,"micro":1}}}})).unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let capabilities: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(capabilities["execute"], "qmp_capabilities");
        assert_eq!(capabilities["id"], 1);
        writeln!(reader.get_mut(), "{}", json!({"return":{},"id":capabilities["id"]})).unwrap();
        assert!(reader.buffer().is_empty());
        reader.into_inner()
    }

    #[test]
    fn qmp_transfers_owned_descriptor_and_skips_events_before_matching_reply() {
        use std::os::fd::AsRawFd;
        let machine = machine();
        let listener = UnixListener::bind(&machine.sockets.api).unwrap();
        let server = std::thread::spawn(move || {
            let mut stream = qmp_peer(listener);
            let (wire, fds) = util::recv_with_fds_by(&stream, 4096, Instant::now() + Duration::from_secs(2)).unwrap();
            let command: Value = serde_json::from_slice(&wire).unwrap();
            assert_eq!(command["execute"], "getfd");
            assert_eq!(command["id"], 2);
            assert_eq!(command["arguments"]["fdname"], "snapshot");
            assert_eq!(fds.len(), 1);
            let mut received = File::from(fds.into_iter().next().unwrap());
            received.write_all(b"receiver").unwrap();
            writeln!(stream, "{}", json!({"event":"STOP"})).unwrap();
            let reply = format!("{}\n", json!({"return":{},"id":command["id"]}));
            let middle = reply.len() / 2;
            stream.write_all(&reply.as_bytes()[..middle]).unwrap();
            std::thread::sleep(Duration::from_millis(1));
            stream.write_all(&reply.as_bytes()[middle..]).unwrap();
        });
        let mut qmp = Qmp::connect(&machine.sockets.api, Instant::now() + Duration::from_secs(2)).unwrap();
        let path = machine.logs.join("descriptor");
        let mut file = File::create_new(&path).unwrap();
        assert_eq!(qmp.command("getfd", json!({"fdname":"snapshot"}), &[file.as_raw_fd()]).unwrap(), json!({}));
        server.join().unwrap();
        file.write_all(b"-sender").unwrap();
        assert_eq!(fs::read(path).unwrap(), b"receiver-sender");
    }

    #[test]
    fn qmp_partial_reply_timeout_permanently_closes_command_admission() {
        let machine = machine();
        let listener = UnixListener::bind(&machine.sockets.api).unwrap();
        let server = std::thread::spawn(move || {
            let mut stream = qmp_peer(listener);
            let _ = util::recv_with_fds_by(&stream, 4096, Instant::now() + Duration::from_secs(2)).unwrap();
            stream.write_all(b"{\"return\":").unwrap();
            // The client must time out and drop this stream, rather than send
            // another command into the partially consumed reply.
            stream.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            assert_eq!(stream.read(&mut [0]).unwrap(), 0);
        });
        let mut qmp = Qmp::connect(&machine.sockets.api, Instant::now() + Duration::from_secs(2)).unwrap();
        assert!(qmp.command("stop", json!({}), &[]).is_err());
        assert!(qmp.command("query-status", json!({}), &[]).unwrap_err().to_string().contains("unusable"));
        drop(qmp);
        server.join().unwrap();
    }

    #[test]
    fn qmp_rejects_mismatched_ids_and_reports_engine_errors() {
        for (case, expected) in [("engine", "device blocks migration"), ("mismatch", "response ID"), ("missing_id", "protocol error")] {
            let machine = machine();
            let listener = UnixListener::bind(&machine.sockets.api).unwrap();
            let server = std::thread::spawn(move || {
                let mut stream = qmp_peer(listener);
                let (wire, fds) = util::recv_with_fds_by(&stream, 4096, Instant::now() + Duration::from_secs(2)).unwrap();
                assert!(fds.is_empty());
                let command: Value = serde_json::from_slice(&wire).unwrap();
                let id = command["id"].as_u64().unwrap();
                let reply = match case {
                    "mismatch" => json!({"return":{},"id":id + 1}),
                    "missing_id" => json!({"error":{"desc":"invalid request"}}),
                    _ => json!({"error":{"desc":"device blocks migration"},"id":id}),
                };
                writeln!(stream, "{reply}").unwrap();
                if case == "engine" {
                    let (wire, _) = util::recv_with_fds_by(&stream, 4096, Instant::now() + Duration::from_secs(2)).unwrap();
                    let command: Value = serde_json::from_slice(&wire).unwrap();
                    assert_eq!(command["id"], id + 1);
                    writeln!(stream, "{}", json!({"return":{"status":"paused"},"id":command["id"]})).unwrap();
                }
            });
            let mut qmp = Qmp::connect(&machine.sockets.api, Instant::now() + Duration::from_secs(2)).unwrap();
            let error = qmp.command("stop", json!({}), &[]).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            let next = qmp.command("query-status", json!({}), &[]);
            if case == "engine" {
                assert_eq!(next.unwrap()["status"], "paused");
            } else {
                assert!(next.unwrap_err().to_string().contains("unusable"));
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn rejects_x86_engines_without_real_mode_nested_paging_fix() {
        for (major, minor, supported) in [(8, 2, false), (9, 1, false), (9, 2, true), (10, 0, true)] {
            let greeting = json!({"QMP":{"version":{"qemu":{"major":major,"minor":minor,"micro":0}}}});
            assert_eq!(check_engine(&greeting, "x86_64").is_ok(), supported);
            assert!(check_engine(&greeting, "aarch64").is_ok());
        }
        assert!(check_engine(&json!({"QMP":{}}), "x86_64").is_err());
    }

    fn machine() -> Machine {
        let key = PathBuf::from(format!("software-test-{}", util::random_hex(16).unwrap()));
        let root = SocketRoot::unique(&key).unwrap();
        let sockets = root.allocate().unwrap();
        let logs = root.dir.join("logs");
        fs::create_dir(&logs).unwrap();
        Machine { processes: Arc::new(Processes::default()), sockets, logs, control: None }
    }

    #[test]
    fn userspace_handshake_waits_for_ok_before_sending_agent_bytes() {
        let machine = machine();
        let listener = UnixListener::bind(&machine.sockets.vsock).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut stream = BufReader::with_capacity(1, stream);
            let mut line = String::new();
            stream.read_line(&mut line).unwrap();
            assert_eq!(line, "CONNECT 52\n");
            stream.get_ref().set_nonblocking(true).unwrap();
            assert_eq!(stream.get_mut().read(&mut [0]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            stream.get_ref().set_nonblocking(false).unwrap();
            stream.get_mut().write_all(b"OK 1234\n").unwrap();
            line.clear();
            stream.read_line(&mut line).unwrap();
            assert_eq!(line, "PING\n");
            stream.get_mut().write_all(&guest::frame(guest::FRAME_MSG, &[b"pong"])).unwrap();
        });
        assert_eq!(machine.message("PING", Instant::now() + Duration::from_secs(2)).unwrap(), b"pong");
        server.join().unwrap();
    }

    #[test]
    fn dropping_engine_owner_kills_reaps_and_finishes_log_readers() {
        let machine = machine();
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf 'engine-started'; exec sleep 60"]);
        machine.processes.spawn(&mut cmd, &machine.logs.join("qemu.log")).unwrap();
        let processes = machine.processes.clone();
        let logs = machine.logs.clone();
        let sockets = machine.sockets.vsock.parent().unwrap().to_path_buf();
        let start = Instant::now();
        drop(machine);
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(processes.0.lock().unwrap().is_empty());
        assert!(!logs.exists());
        assert!(!sockets.exists());
    }

    #[test]
    fn engine_death_is_reported_without_waiting_for_agent_deadline() {
        let machine = machine();
        machine.processes.spawn(Command::new("false").arg("ignored"), &machine.logs.join("qemu.log")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Err(e) = machine.processes.alive() {
                assert!(e.to_string().contains("exited"), "{e}");
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn dead_engine_ends_exec_even_when_backend_holds_its_socket_open() {
        struct InterruptedOnce(std::os::unix::net::UnixStream, bool);
        impl Read for InterruptedOnce {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.1 {
                    self.1 = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.0.read(buf)
            }
        }
        let machine = machine();
        machine.processes.spawn(Command::new("false").arg("ignored"), &machine.logs.join("qemu.log")).unwrap();
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        stream.set_read_timeout(Some(Duration::from_millis(25))).unwrap();
        let mut watched = Watched { reader: InterruptedOnce(stream, false), processes: &machine.processes };
        let started = Instant::now();
        let error = watched.read(&mut [0]).unwrap_err();
        assert!(error.to_string().contains("exited"), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
