//! Software execution with QEMU TCG and a userspace virtio-vsock backend.
//!
//! This cold-boot path owns both processes. Its state is separate from Firecracker
//! templates/checkpoints; native QEMU vhost-user-vsock is not yet migratable.
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
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

    fn alive(&self) -> Result<()> {
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
                "x86_64" => ("q35", "max,svm=on,enforce=on", "ttyS0", "virtio-blk-pci", "vhost-user-vsock-pci", "virtio-net-pci"),
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
            crate::info!("software: agent ready, checking pause/resume");
            // Verify actual machine pause/resume, not host SIGSTOP/SIGCONT.
            machine.switch("stop", deadline)?;
            machine.switch("cont", deadline)?;
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

impl Machine {
    /// vhost-device-vsock 0.3 reads ahead and discards bytes after CONNECT.
    /// Wait for its OK before writing the agent command; Firecracker keeps its
    /// existing pipelined handshake and does not pay this extra round trip.
    fn request(&self, line: &str, deadline: Instant) -> Result<BufReader<std::os::unix::net::UnixStream>> {
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

    fn message(&self, line: &str, deadline: Instant) -> Result<Vec<u8>> {
        let mut r = self.request(line, deadline)?;
        match guest::read_frame(&mut By { s: &mut r, at: deadline })? {
            Some((guest::FRAME_MSG, m)) => Ok(m),
            other => bail!("unexpected software guest reply: {other:?}"),
        }
    }

    fn switch(&mut self, command: &str, deadline: Instant) -> Result<()> {
        let stream = util::connect_unix(&self.sockets.api, remaining(deadline)?)?;
        let mut r = BufReader::new(By { s: stream, at: deadline });
        fn reply(r: &mut impl BufRead) -> Result<Value> {
            loop {
                let mut line = String::new();
                if r.take(1 << 20).read_line(&mut line)? == 0 || !line.ends_with('\n') {
                    bail!("QMP disconnected or reply too long");
                }
                let v: Value = serde_json::from_str(&line)?;
                if !v["error"].is_null() {
                    bail!("QMP refused operation: {}", v["error"]);
                }
                if v["event"].is_null() {
                    return Ok(v);
                }
            }
        }
        if reply(&mut r)?["QMP"].is_null() {
            bail!("missing QMP greeting");
        }
        for action in ["qmp_capabilities", command] {
            r.get_mut().write_all(format!("{{\"execute\":\"{action}\"}}\n").as_bytes())?;
            reply(&mut r)?;
        }
        r.get_mut().write_all(b"{\"execute\":\"query-status\"}\n")?;
        let state = reply(&mut r)?;
        let expected = if command == "stop" { "paused" } else { "running" };
        if state["return"]["status"] != expected {
            bail!("QMP did not enter {expected}: {state}");
        }
        Ok(())
    }

    pub fn exec(&self, argv: Vec<String>, out: impl FnMut(u8, &[u8]) -> Result<()>) -> Result<i32> {
        let body = guest::Exec { argv, ..Default::default() }.encode()?;
        guest::fits(&body)?;
        let id = util::random_hex(16)?;
        let deadline = Instant::now() + guest::TIMEOUT;
        let r = guest::session_on("argv", &id, 0, &body, |line| self.request(line, deadline))?;
        guest::untimed(&r)?;
        r.get_ref().set_read_timeout(Some(Duration::from_millis(250)))?;
        guest::exec_output(&mut Watched { reader: r, processes: &self.processes }, &id, out)
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
