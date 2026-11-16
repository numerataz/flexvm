//! Software execution with QEMU TCG and a userspace virtio-vsock backend.
//!
//! This cold-boot path owns both processes. Its state is separate from Firecracker
//! templates/checkpoints; native QEMU vhost-user-vsock is not yet migratable.
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::socket::{SocketRoot, Sockets};
use crate::util::{By, Result};
use crate::{bail, guest, software_state, template, util};

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
        self.spawn_with_fds(cmd, log, &[])
    }

    fn spawn_with_fds(&self, cmd: &mut Command, log: &Path, inherited: &[RawFd]) -> Result<()> {
        template::interrupted()?;
        File::create(log)?;
        let (mut reader, writer) = std::io::pipe()?;
        cmd.stdin(Stdio::null()).stdout(writer.try_clone()?).stderr(writer);
        let parent = unsafe { libc::getpid() };
        let inherited = inherited.to_vec();
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
                for fd in &inherited {
                    let flags = libc::fcntl(*fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
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

#[derive(Default, PartialEq)]
enum Capture {
    #[default]
    None,
    Exported,
    Uncertain,
}

struct Endpoints<'a> {
    api: &'a Path,
    control: &'a Path,
    backend: &'a Path,
    firmware: &'a Path,
}

pub struct Machine {
    inputs: Option<software_state::Inputs>,
    profile: software_state::Profile,
    engine_version: Value,
    capture: Mutex<Capture>,
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
        self.validate_limits()?;
        if !self.kernel.is_file() {
            bail!("software kernel is not a file: {}", self.kernel.display());
        }
        Ok(())
    }

    fn validate_limits(&self) -> Result<()> {
        if !(128..=1_048_576).contains(&self.mem_mib) {
            bail!("software --mem must be 128..1048576 MiB");
        }
        if !(1..=256).contains(&self.vcpus) {
            bail!("software --vcpus must be 1..256");
        }
        if self.boot_timeout.is_zero() || self.boot_timeout > Duration::from_secs(3600) {
            bail!("software --timeout must be 1..3600 seconds (boot only)");
        }
        Ok(())
    }

    fn command(&self, engine: &Path, kernel: &Path, rootfs: &Path, endpoints: &Endpoints<'_>) -> Result<Command> {
        let arch = std::env::consts::ARCH;
        let (board, cpu, console, block, vsock, nic) = match arch {
            // TCG implements AMD SVM: the ordinary guest Linux KVM driver
            // supplies the ABI without a host KVM device. Enforce support
            // instead of silently losing guest virtualization capabilities.
            "x86_64" => ("q35", "max,svm=on,npt=on,enforce=on", "ttyS0", "virtio-blk-pci", "vhost-user-vsock-pci", "virtio-net-pci"),
            "aarch64" => ("virt,virtualization=on,gic-version=3", "cortex-a72", "ttyAMA0", "virtio-blk-device", "vhost-user-vsock-device", "virtio-net-device"),
            _ => bail!("software execution is not implemented for {arch}"),
        };
        let mut cmd = Command::new(engine);
        cmd.arg("-L").arg(endpoints.firmware);
        cmd.args(["-machine", &format!("{board},memory-backend=ram"), "-accel", "tcg,thread=multi", "-cpu", cpu]);
        cmd.args(["-m", &self.mem_mib.to_string(), "-smp", &self.vcpus.to_string()]);
        cmd.args(["-object", &json!({"qom-type":"memory-backend-memfd", "id":"ram", "size":u64::from(self.mem_mib)<<20, "share":true}).to_string()]);
        cmd.args(["-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot"]);
        cmd.args(["-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]);
        let control_arg = if self.control == Control::Serial { " flexvm.control=serial" } else { "" };
        cmd.arg("-kernel").arg(kernel).args([
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
            cmd.args(["-chardev", &format!("socket,id=vsock,path={}", endpoints.backend.display()), "-device", &format!("{vsock},chardev=vsock")]);
        } else {
            let device = if arch == "x86_64" { "virtio-serial-pci" } else { "virtio-serial-device" };
            cmd.args(["-device", &format!("{device},id=controlbus")]);
            cmd.args(["-chardev", &format!("socket,id=control,path={},server=on,wait=off", endpoints.control.display())]);
            cmd.args(["-device", &format!("virtserialport,bus=controlbus.0,chardev=control,name={}", control::PORT_NAME)]);
        }
        // Match the agent's existing static gateway and /32 configuration.
        cmd.args([
            "-netdev",
            "user,id=net,net=169.254.0.0/16,host=169.254.1.1,dns=169.254.1.3,dhcpstart=169.254.1.2,ipv6=off",
            "-device",
            &format!("{nic},netdev=net"),
        ]);
        cmd.args(["-qmp", &format!("unix:{},server=on,wait=off", endpoints.api.display())]);
        Ok(cmd)
    }

    pub fn profile(&self) -> Result<software_state::Profile> {
        let endpoints =
            Endpoints { api: Path::new("@qmp"), control: Path::new("@control"), backend: Path::new("@vsock-backend"), firmware: Path::new("@firmware") };
        let command = self.command(Path::new("@engine"), Path::new("@kernel"), Path::new("@rootfs"), &endpoints)?;
        Ok(software_state::Profile {
            architecture: std::env::consts::ARCH.into(),
            arguments: command
                .get_args()
                .map(|arg| arg.to_str().map(str::to_owned).ok_or_else(|| "software profile contains a non-UTF8 argument".into()))
                .collect::<Result<_>>()?,
        })
    }

    pub fn boot(&self, rootfs: &Path, processes: Arc<Processes>) -> Result<Machine> {
        let inputs = software_state::Inputs::open(&self.qemu, &self.kernel, rootfs)?;
        self.launch(inputs, processes, None)
    }

    /// Load state into a fresh engine, with CPUs paused and public admission closed.
    pub fn restore(&self, verified: software_state::Verified, processes: Arc<Processes>) -> Result<Machine> {
        if self.control != Control::Serial {
            bail!("software restore requires serial control");
        }
        if self.profile()? != verified.manifest.profile {
            bail!("software restore configuration changed after artifact validation");
        }
        self.launch(verified.inputs, processes, Some((&verified.state.file, &verified.manifest.engine_version)))
    }

    fn launch(&self, inputs: software_state::Inputs, processes: Arc<Processes>, incoming: Option<(&File, &Value)>) -> Result<Machine> {
        // Restore uses pinned artifacts and does not require the original input paths.
        self.validate_limits()?;
        inputs.engine.unchanged()?;
        inputs.kernel.unchanged()?;
        inputs.rootfs.unchanged()?;
        let profile = self.profile()?;
        let key = PathBuf::from(format!("software-{}-{}", std::process::id(), util::random_hex(16)?));
        let root = SocketRoot::unique(&key)?;
        let sockets = root.allocate()?;
        let logs = root.dir.join("logs");
        fs::create_dir(&logs)?;
        let kernel = PathBuf::from(format!("/proc/self/fd/{}", inputs.kernel.file.as_raw_fd()));
        let rootfs = PathBuf::from(format!("/proc/self/fd/{}", inputs.rootfs.file.as_raw_fd()));
        let engine = PathBuf::from(format!("/proc/self/fd/{}", inputs.engine.file.as_raw_fd()));
        let mut inherited = vec![inputs.engine.file.as_raw_fd(), inputs.kernel.file.as_raw_fd(), inputs.rootfs.file.as_raw_fd()];
        let mut machine =
            Machine { inputs: Some(inputs), profile, engine_version: Value::Null, capture: Mutex::default(), processes, sockets, logs, control: None };
        let firmware = machine.logs.join("firmware");
        let result = (|| -> Result<()> {
            fs::create_dir(&firmware)?;
            for (name, input) in &machine.inputs.as_ref().ok_or("software inputs are missing")?.firmware {
                input.unchanged()?;
                let fd = input.file.as_raw_fd();
                inherited.push(fd);
                std::os::unix::fs::symlink(format!("/proc/self/fd/{fd}"), firmware.join(name))?;
            }
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
            let endpoints = Endpoints { api: &machine.sockets.api, control: &machine.sockets.vsock, backend: &machine.sockets.uffd, firmware: &firmware };
            let mut cmd = self.command(&engine, &kernel, &rootfs, &endpoints)?;
            if incoming.is_some() {
                cmd.args(["-incoming", "defer", "-S"]);
            }
            machine.processes.spawn_with_fds(&mut cmd, &machine.logs.join("qemu.log"), &inherited)?;
            while !machine.sockets.api.exists() {
                machine.processes.alive()?;
                remaining(deadline)?;
                std::thread::sleep(Duration::from_millis(10));
            }
            let mut qmp = Qmp::connect(&machine.sockets.api, deadline)?;
            machine.engine_version = qmp.command("query-version", json!({}), &[])?;
            if let Some((state, expected_version)) = incoming {
                if machine.engine_version != *expected_version {
                    bail!("software engine version differs from the captured profile");
                }
                qmp.command("getfd", json!({"fdname":"restore"}), &[state.as_raw_fd()])?;
                qmp.command("migrate-incoming", json!({"uri":"fd:restore"}), &[])?;
                machine.wait_migration(&mut qmp, deadline, true)?;
                let status = qmp.command("query-status", json!({}), &[])?;
                if status["running"] != false || status["status"] != "paused" {
                    bail!("restored engine is not paused: {status}");
                }
                return Ok(());
            }
            drop(qmp);
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
        bail!("software VM operation timed out");
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
        let stream = loop {
            match util::connect_unix(path, remaining(deadline)?) {
                Ok(stream) => break stream,
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ECONNREFUSED)) => {
                    remaining(deadline)?;
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e.into()),
            }
        };
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
    /// The caller owns the admission/CPU boundary and the output artifact. A
    /// failed export does not authorize source resume: cancel and verify first.
    pub fn save(&self, state: &File, deadline: Instant) -> Result<()> {
        let mut capture = self.capture.lock().unwrap();
        if *capture != Capture::None {
            bail!("software state capture is unresolved");
        }
        let mut qmp = Qmp::connect(&self.sockets.api, deadline)?;
        let status = qmp.command("query-status", json!({}), &[])?;
        if status["running"] != false || status["status"] != "paused" {
            bail!("software state capture requires a paused engine: {status}");
        }
        // Neither a completed export nor an ambiguous failure can be undone by
        // an ordinary cont. The owner must either retire this engine or resolve
        // the capture before explicitly authorizing source execution again.
        *capture = Capture::Uncertain;
        qmp.command("migrate-set-parameters", json!({"max-bandwidth":64u64 << 30}), &[])?;
        qmp.command("getfd", json!({"fdname":"snapshot"}), &[state.as_raw_fd()])?;
        qmp.command("migrate", json!({"uri":"fd:snapshot"}), &[])?;
        self.wait_migration(&mut qmp, deadline, false)?;
        *capture = Capture::Exported;
        Ok(())
    }

    /// Only an owner that still holds CPU/disk authority may use this rollback.
    /// It is forbidden once the artifact or a transfer grants another owner execution.
    pub fn resume_source(&self, deadline: Instant) -> Result<()> {
        let mut capture = self.capture.lock().unwrap();
        if *capture == Capture::None {
            bail!("software VM has no capture to resolve");
        }
        let result = (|| {
            let mut qmp = Qmp::connect(&self.sockets.api, deadline)?;
            let mut cancelling = false;
            loop {
                self.processes.alive()?;
                remaining(deadline)?;
                let state = qmp.command("query-migrate", json!({}), &[])?;
                match state["status"].as_str() {
                    None | Some("none" | "cancelled" | "failed" | "completed") => break,
                    Some("setup" | "active" | "device" | "wait-unplug" | "cancelling") => {
                        if !cancelling {
                            qmp.command("migrate_cancel", json!({}), &[])?;
                            cancelling = true;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    _ => bail!("cannot resolve software capture: {state}"),
                }
            }
            let status = qmp.command("query-status", json!({}), &[])?;
            if status["running"] != false || !matches!(status["status"].as_str(), Some("paused" | "postmigrate")) {
                bail!("source is not fenced at a paused capture boundary: {status}");
            }
            qmp.command("cont", json!({}), &[])?;
            let status = qmp.command("query-status", json!({}), &[])?;
            if status["running"] != true || status["status"] != "running" {
                bail!("software source did not resume: {status}");
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                *capture = Capture::None;
                Ok(())
            }
            Err(error) => {
                *capture = Capture::Uncertain;
                self.processes.stop();
                Err(error)
            }
        }
    }

    fn wait_migration(&self, qmp: &mut Qmp, deadline: Instant, incoming: bool) -> Result<()> {
        loop {
            self.processes.alive()?;
            remaining(deadline)?;
            let state = qmp.command("query-migrate", json!({}), &[])?;
            match state["status"].as_str() {
                Some("completed") => return Ok(()),
                Some("setup" | "active" | "device" | "wait-unplug") => {}
                None | Some("none") if incoming => {}
                _ => bail!("software state transfer failed: {state}"),
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn disconnect_control(&mut self) {
        self.control.take();
    }

    pub fn reconnect_control(&mut self, deadline: Instant) -> Result<()> {
        if self.control.is_some() {
            bail!("software control is already connected");
        }
        let stream = util::connect_unix(&self.sockets.vsock, remaining(deadline)?)?;
        self.control = Some(control::Client::connect(stream)?);
        Ok(())
    }

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
        let capture = self.capture.lock().unwrap();
        if *capture != Capture::None {
            bail!("software state capture must be resolved before changing CPU state");
        }
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
    fn unresolved_capture_blocks_ordinary_resume_and_cancellation_is_verified() {
        let machine = machine();
        *machine.capture.lock().unwrap() = Capture::Exported;
        assert!(machine.switch("cont", Instant::now() + Duration::from_secs(2)).is_err());
        let listener = UnixListener::bind(&machine.sockets.api).unwrap();
        let server = std::thread::spawn(move || {
            let mut reader = BufReader::new(qmp_peer(listener));
            for (command, result) in [
                ("query-migrate", json!({"status":"active"})),
                ("migrate_cancel", json!({})),
                ("query-migrate", json!({"status":"cancelled"})),
                ("query-status", json!({"status":"paused","running":false})),
                ("cont", json!({})),
                ("query-status", json!({"status":"running","running":true})),
            ] {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(request["execute"], command);
                writeln!(reader.get_mut(), "{}", json!({"return":result,"id":request["id"]})).unwrap();
            }
        });
        machine.resume_source(Instant::now() + Duration::from_secs(2)).unwrap();
        assert!(*machine.capture.lock().unwrap() == Capture::None);
        server.join().unwrap();
    }

    /// Run explicitly with the native pinned kernel and a local OCI state-probe image.
    /// This is the actual image preparation + guest agent path, not a replacement init.
    #[test]
    #[ignore = "requires root, native QEMU, kernel and state-probe OCI image"]
    fn real_agent_cold_restore_preserves_process_ram_and_sessions() {
        use std::os::unix::fs::DirBuilderExt;
        let image = std::env::var("FLEXVM_SOFTWARE_TEST_IMAGE").expect("local state-probe OCI image");
        let kernel = std::env::var_os("FLEXVM_SOFTWARE_TEST_KERNEL").expect("native FlexVM kernel");
        let dir = PathBuf::from(format!("/var/lib/flexvm-state-test-{}", util::random_hex(16).unwrap()));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let options = crate::image::Options { image, staging: dir.join("staging"), ..Default::default() };
        let (rootfs, meta, _reservation, _use_lock) = crate::image::prepare(&dir.join("images"), None, &options).unwrap();
        let mut config = Config {
            control: Control::Serial,
            kernel: kernel.into(),
            qemu: std::env::var("FLEXVM_SOFTWARE_TEST_QEMU").unwrap_or_else(|_| format!("qemu-system-{}", std::env::consts::ARCH)),
            vsock_backend: String::new(),
            mem_mib: 512,
            vcpus: 1,
            boot_timeout: Duration::from_secs(60),
        };
        let source = Arc::new(Processes::default());
        let mut machine = config.boot(&rootfs, source.clone()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        assert_eq!(machine.message("FENCE 1 42", deadline).unwrap(), b"ok 1");
        let (id, mut output) = machine.start_exec(meta.argv.clone()).unwrap();
        machine.exec_started(&mut output, &id).unwrap();
        fn observation(machine: &Machine, deadline: Instant) -> Vec<u64> {
            loop {
                assert!(Instant::now() < deadline);
                let mut bytes = Vec::new();
                let code = machine
                    .exec(vec!["/state-probe".into(), "status".into()], |_, data| {
                        bytes.extend_from_slice(data);
                        Ok(())
                    })
                    .unwrap();
                if code == 0 {
                    return String::from_utf8(bytes).unwrap().split_whitespace().map(|n| n.parse().unwrap()).collect();
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let before = observation(&machine, deadline);
        assert_eq!(before.len(), 5);
        assert_eq!(machine.message("BARRIER 1 QUIESCE 1 42 1", deadline).unwrap(), b"ok BARRIER 1 QUIESCED 1 1");
        drop(output);
        machine.disconnect_control();
        // Wait for the guest to discard the old Yamux parser and arm a fresh
        // serial transport before saving it. A new owner cannot reuse its peer.
        loop {
            assert!(Instant::now() < deadline, "guest serial reset did not finish");
            let log = fs::read_to_string(machine.logs.join("qemu.log")).unwrap();
            if log.lines().filter(|line| line.contains("flexvm-init: serial control ready")).count() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        machine.switch("stop", deadline).unwrap();
        let staging = software_state::Staging::new(&dir).unwrap();
        machine.save(&staging.state, deadline).unwrap();
        assert!(machine.switch("cont", deadline).unwrap_err().to_string().contains("capture must be resolved"));
        let blank = software_state::Artifact { bytes: 0, sha256: String::new() };
        let manifest = software_state::Manifest {
            format: 1,
            backend: "qemu-tcg".into(),
            vm_id: util::random_hex(16).unwrap(),
            owner_generation: 1,
            saved_epoch: 42,
            barrier_sequence: 1,
            profile: machine.profile.clone(),
            engine_version: machine.engine_version.clone(),
            engine: blank.clone(),
            kernel: blank.clone(),
            rootfs: blank.clone(),
            state: blank,
            firmware: std::collections::BTreeMap::new(),
            main: software_state::Session { id: id.clone(), offset: 0, claim: 0 },
            image: meta,
        };
        let checkpoint = dir.join("checkpoint");
        staging.commit(&checkpoint, machine.inputs.as_ref().unwrap(), manifest).unwrap();
        let old_engine = source.engine_ident().unwrap();
        source.stop();
        drop(machine);
        assert!(!old_engine.alive());
        let verified = software_state::open(&checkpoint, &config.profile().unwrap()).unwrap();
        fs::rename(&checkpoint, dir.join("saved-artifacts")).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&checkpoint).unwrap();
        config.kernel = PathBuf::from("/missing-original-kernel");
        config.qemu = "/missing-original-engine".into();
        let target = Arc::new(Processes::default());
        let mut machine = config.restore(verified, target).unwrap();
        machine.switch("cont", deadline).unwrap();
        machine.reconnect_control(deadline).unwrap();
        assert_eq!(machine.message("PING", deadline).unwrap(), b"pong");
        assert_eq!(machine.message("FENCE 2 84", deadline).unwrap(), b"ok 2");
        assert_ne!(machine.message("FENCE 1 42", deadline).unwrap(), b"ok 1");
        assert_ne!(machine.message("BARRIER 1 RESUME 2 84 1 99", deadline).unwrap(), b"ok BARRIER 1 RESUMED 1 99");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let clock = format!("BARRIER 1 MAINT 2 84 CLOCK {}.{:09}", now.as_secs(), now.subsec_nanos());
        assert!(machine.message(&clock, deadline).unwrap().starts_with(b"ok "));
        assert_eq!(machine.message("BARRIER 1 RESUME 2 84 1 1", deadline).unwrap(), b"ok BARRIER 1 RESUMED 1 1");
        let after = loop {
            let seen = observation(&machine, deadline);
            if seen[3] > before[3] {
                break seen;
            }
        };
        assert_eq!(&before[..3], &after[..3], "PID, start time or random RAM canary changed");
        assert!(after[4] >= before[4], "guest monotonic clock went backwards");
        let line = guest::attach_line(&id, 0, 1, 84, guest::AttachForm::Epoch, false).unwrap();
        let mut session = machine.request(&line, deadline).unwrap();
        assert_eq!(guest::read_frame(&mut By { s: &mut session, at: deadline }).unwrap(), Some((guest::FRAME_MSG, id.into_bytes())));
        let mut live_output = Vec::new();
        loop {
            let (kind, data) = guest::read_frame(&mut By { s: &mut session, at: deadline }).unwrap().unwrap();
            if kind == guest::FRAME_STDOUT {
                live_output.extend_from_slice(&data[8..]);
                let text = String::from_utf8_lossy(&live_output);
                if text.lines().filter_map(|line| line.strip_prefix("STATE_TICK ")).filter_map(|n| n.parse::<u64>().ok()).any(|n| n > after[3]) {
                    assert_eq!(text.matches("STATE_WORKLOAD_BOOT").count(), 1);
                    break;
                }
            }
        }
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
        Machine {
            inputs: None,
            profile: software_state::Profile { architecture: std::env::consts::ARCH.into(), arguments: Vec::new() },
            engine_version: Value::Null,
            capture: Mutex::default(),
            processes: Arc::new(Processes::default()),
            sockets,
            logs,
            control: None,
        }
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
