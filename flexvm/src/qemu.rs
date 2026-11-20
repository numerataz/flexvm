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
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::socket::{SocketRoot, Sockets};
use crate::util::{By, Result};
use crate::{bail, guest, software_state, template, util, volume};

#[path = "../../guest/src/control.rs"]
#[allow(dead_code)]
mod control;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Vsock,
    Serial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Private,
    Legacy,
}

impl Network {
    fn netdev(self) -> &'static str {
        match self {
            Self::Private => "user,id=net,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15,ipv6=off",
            Self::Legacy => "user,id=net,net=169.254.0.0/16,host=169.254.1.1,dns=169.254.1.3,dhcpstart=169.254.1.2,ipv6=off",
        }
    }

    pub fn ip(self) -> std::net::Ipv4Addr {
        match self {
            Self::Private => std::net::Ipv4Addr::new(10, 0, 2, 15),
            Self::Legacy => std::net::Ipv4Addr::new(169, 254, 1, 2),
        }
    }

    fn dns(self) -> &'static str {
        match self {
            Self::Private => "10.0.2.3",
            Self::Legacy => "169.254.1.3",
        }
    }

    fn kernel_arg(self) -> &'static str {
        match self {
            Self::Private => " flexvm.gateway4=10.0.2.2",
            Self::Legacy => "",
        }
    }

    /// Metadata only; execution still requires equality with a full locally built profile.
    pub fn from_profile(profile: &software_state::Profile) -> Option<Self> {
        let value = profile.arguments.windows(2).find(|args| args[0] == "-netdev")?.get(1)?;
        [Self::Private, Self::Legacy].into_iter().find(|network| network.netdev() == value)
    }
}

pub struct ParentKvm {
    pub bundle: PathBuf,
    pub engine: String,
    pub child_mem_mib: u32,
}

impl ParentKvm {
    fn command(
        &self,
        qemu: Command,
        inherited: &[RawFd],
        incoming: Option<&Incoming<'_>>,
        runtime: &SocketRoot,
        memory: u32,
        qmp: &Path,
    ) -> Result<(Command, software_state::Input, Option<software_state::Input>)> {
        let directory = runtime.dir.join("logs/parent-kvm");
        fs::create_dir(&directory)?;
        let saved = incoming.and_then(|state| state.parent);
        let bundle = directory.join("bundle");
        let frontend = self.stage_frontend(&bundle, saved)?;
        let native_worker = if saved.is_some() && self.engine == "kvm" {
            let worker = software_state::Input::open(&self.bundle.join("native-worker").canonicalize()?)?;
            // The runtime directory can be mounted noexec. Keep a descriptor
            // for the locally trusted executable throughout the owner lifetime.
            let pinned = format!("/proc/{}/fd/{}", std::process::id(), worker.file.as_raw_fd());
            std::os::unix::fs::symlink(pinned, bundle.join("native-worker"))?;
            Some(worker)
        } else {
            None
        };
        let broker = directory.join("parent-kvm-run.py");
        fs::write(&broker, include_bytes!("../../scripts/compat/parent-kvm-run.py"))?;
        fs::write(directory.join("software-boot.py"), include_bytes!("../../scripts/compat/software-boot.py"))?;
        #[cfg(target_arch = "aarch64")]
        {
            fs::write(directory.join("arm-parent-run.py"), include_bytes!("../../scripts/compat/arm-parent-run.py"))?;
            fs::write(directory.join("arm-tcg-worker.py"), include_bytes!("../../scripts/compat/arm-tcg-worker.py"))?;
        }
        let mut cmd = Command::new("python3");
        cmd.arg("-I").arg(broker).args(["--serve", "--bundle"]).arg(bundle).arg("--output").arg(directory);
        cmd.arg("--control").arg(runtime.dir.join("k")).arg("--outer-qmp").arg(qmp);
        cmd.args(["--outer-memory", &memory.to_string(), "--child-memory", &self.child_mem_mib.to_string(), "--engine", &self.engine]);
        let pinned_engine = inherited.first().ok_or("missing parent KVM emulator descriptor")?;
        cmd.args(["--emulator-fd", &pinned_engine.to_string()]);
        if let Some(fds) = incoming.and_then(Incoming::parent_fds) {
            cmd.arg("--restore-fds").args(fds.map(|fd| fd.to_string()));
        }
        for fd in inherited {
            cmd.arg("--inherit").arg(fd.to_string());
        }
        cmd.arg("--").arg(qemu.get_program()).args(qemu.get_args());
        Ok((cmd, frontend, native_worker))
    }

    fn stage_frontend(&self, bundle: &Path, saved: Option<&software_state::ParentInputs>) -> Result<software_state::Input> {
        fs::create_dir(bundle)?;
        let frontend = bundle.join("flexvm-pvkvm.img");
        if let Some(saved) = saved {
            saved.frontend.copy_to(&frontend, false)?;
            fs::write(bundle.join("checkpoint.version"), b"1\n")?;
        } else {
            software_state::Input::open(&self.bundle.join("flexvm-pvkvm.img").canonicalize()?)?.copy_to(&frontend, false)?;
            let marker = self.bundle.join("checkpoint.version");
            if fs::read(marker).is_ok_and(|bytes| bytes == b"1\n") {
                fs::write(bundle.join("checkpoint.version"), b"1\n")?;
            }
            let worker = self.bundle.join("native-worker");
            if worker.is_file() {
                std::os::unix::fs::symlink(worker, bundle.join("native-worker"))?;
            }
        }
        software_state::Input::open(&frontend)
    }
}

pub struct Config {
    pub control: Control,
    pub kernel: PathBuf,
    pub qemu: String,
    pub vsock_backend: String,
    pub mem_mib: u32,
    pub max_mib: u32,
    pub vcpus: u32,
    pub boot_timeout: Duration,
    pub parent_kvm: Option<ParentKvm>,
}

/// Children remain unreaped until their owner observes exit, so their pids cannot
/// be reused while cancellation holds this mutex.
#[derive(Default)]
pub struct Processes {
    children: Mutex<Vec<Process>>,
    leases: Mutex<Vec<File>>,
    runtime: Mutex<Option<Weak<SocketRoot>>>,
}

struct Process {
    child: Child,
    ident: Option<crate::host::Ident>,
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
    pub fn inherit_lease(&self, file: File) {
        self.leases.lock().unwrap().push(file);
    }

    pub fn stop(&self) {
        let mut children = self.children.lock().unwrap();
        while let Some(child) = children.pop() {
            drop(child);
        }
    }

    fn spawn(&self, cmd: &mut Command, log: &Path) -> Result<()> {
        self.spawn_kind(cmd, log, &[], crate::socket::SoftwareKind::VhostUserVsock)
    }

    fn spawn_with_fds(&self, cmd: &mut Command, log: &Path, inherited: &[RawFd]) -> Result<()> {
        self.spawn_kind(cmd, log, inherited, crate::socket::SoftwareKind::QemuTcg)
    }

    fn spawn_kind(&self, cmd: &mut Command, log: &Path, inherited: &[RawFd], kind: crate::socket::SoftwareKind) -> Result<()> {
        template::interrupted()?;
        File::create(log)?;
        let (mut reader, writer) = std::io::pipe()?;
        cmd.stdin(Stdio::null()).stdout(writer.try_clone()?).stderr(writer);
        let runtime = self.runtime.lock().unwrap().as_ref().and_then(Weak::upgrade);
        let mut leases = self.leases.lock().unwrap().iter().map(File::try_clone).collect::<std::io::Result<Vec<_>>>()?;
        if let Some(runtime) = &runtime {
            leases.push(runtime.software_lease()?);
        }
        let parent = unsafe { libc::getpid() };
        let inherited = inherited.iter().copied().chain(leases.iter().map(AsRawFd::as_raw_fd)).collect::<Vec<_>>();
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
        let mut children = self.children.lock().unwrap();
        // Cancellation may have arrived while opening logs/building the command.
        template::interrupted()?;
        let child = util::unblock_signals_in(cmd).spawn();
        // The command must not keep the pipe open after the engine exits.
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let child = child?;
        let ident = crate::host::Ident::of(child.id());
        let mut process = Process { child, ident, logging: None };
        if let Some(runtime) = runtime {
            runtime.record_software_child(children.len(), kind, process.ident.clone().ok_or("cannot identify software child")?)?;
        }
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

    fn recorded_engine(&self) -> Result<crate::host::Ident> {
        let children = self.children.lock().unwrap();
        children.last().and_then(|child| child.ident.clone()).ok_or_else(|| "cannot identify software engine process".into())
    }

    pub fn engine_ident(&self) -> Result<crate::host::Ident> {
        let ident = self.recorded_engine()?;
        if crate::host::PidFd::open(&ident)?.is_none() {
            bail!("software engine has exited");
        }
        Ok(ident)
    }

    /// Join the engine logger only after actual process exit, so shutdown
    /// classification sees its final console bytes and never blocks a live VM.
    fn engine_status(&self) -> Result<Option<ExitStatus>> {
        let mut children = self.children.lock().unwrap();
        let engine = children.last_mut().ok_or("software engine is retired")?;
        let status = engine.child.try_wait()?;
        if status.is_some() {
            if let Some(logging) = engine.logging.take() {
                logging.join().map_err(|_| "software engine logger panicked")?;
            }
        }
        Ok(status)
    }

    pub fn alive(&self) -> Result<()> {
        template::interrupted()?;
        for process in self.children.lock().unwrap().iter_mut() {
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
    disks: Vec<volume::Writer>,
    profile: software_state::Profile,
    network: Network,
    engine_version: Value,
    capture: Mutex<Capture>,
    processes: Arc<Processes>,
    sockets: Sockets,
    logs: PathBuf,
    transport: Control,
    control: Mutex<Option<control::Client>>,
    parent_provider: bool,
    parent_fence: Option<ParentFence>,
    parent_frontend: Option<software_state::Input>,
    _native_worker: Option<software_state::Input>,
    parent_memory_mib: u32,
}

struct Incoming<'a> {
    state: &'a File,
    version: &'a Value,
    parent: Option<&'a software_state::ParentInputs>,
}

impl Incoming<'_> {
    fn parent_fds(&self) -> Option<[RawFd; 3]> {
        self.parent.map(|parent| [self.state.as_raw_fd(), parent.worker.file.as_raw_fd(), parent.broker.file.as_raw_fd()])
    }
}

struct ParentFence {
    path: PathBuf,
    lease: Mutex<Option<UnixStream>>,
}

impl ParentFence {
    fn request(socket: &UnixStream, command: &[u8], fds: &[RawFd], deadline: Instant) -> Result<bool> {
        util::send_with_fds(socket, command, fds, deadline)?;
        socket.set_read_timeout(Some(remaining(deadline)?))?;
        let mut reply = [0; 64];
        let (received, fds) = util::recvmsg_fds(socket.as_raw_fd(), &mut reply)?;
        let native = command == b"check-save" && &reply[..received] == b"ok:kvm";
        if !fds.is_empty() || (&reply[..received] != b"ok" && !native) {
            bail!("parent KVM broker rejected {}: {}", String::from_utf8_lossy(command), String::from_utf8_lossy(&reply[..received]));
        }
        Ok(native)
    }

    fn acquire(&self, command: &[u8], deadline: Instant) -> Result<()> {
        let mut lease = self.lease.lock().unwrap();
        if lease.is_none() {
            let socket = util::connect_unix_kind(&self.path, remaining(deadline)?, libc::SOCK_SEQPACKET)?;
            Self::request(&socket, command, &[], deadline)?;
            *lease = Some(socket);
            crate::info!("software: parent KVM vCPUs quiesced");
        }
        Ok(())
    }

    fn check_save(&self, deadline: Instant) -> Result<bool> {
        let lease = self.lease.lock().unwrap();
        let socket = lease.as_ref().ok_or("parent KVM checkpoint has no owner lease")?;
        Self::request(socket, b"check-save", &[], deadline)
    }

    fn save(&self, fds: &[RawFd; 3], deadline: Instant) -> Result<()> {
        let lease = self.lease.lock().unwrap();
        let socket = lease.as_ref().ok_or("parent KVM checkpoint has no owner lease")?;
        Self::request(socket, b"save", fds, deadline).map(|_| ())
    }

    fn rollback(&self, deadline: Instant) -> Result<()> {
        let lease = self.lease.lock().unwrap();
        let socket = lease.as_ref().ok_or("parent KVM rollback has no owner lease")?;
        Self::request(socket, b"rollback", &[], deadline).map(|_| ())
    }

    fn thaw(&self, deadline: Instant) -> Result<()> {
        let mut lease = self.lease.lock().unwrap();
        if let Some(socket) = lease.as_ref() {
            Self::request(socket, b"thaw", &[], deadline)?;
            lease.take();
        }
        Ok(())
    }
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
        self.control.get_mut().unwrap().take();
        let _ = fs::remove_dir_all(&self.logs);
    }
}

/// Default initial boot RAM for elastic software VMs before virtio-mem growth.
pub const ELASTIC_BASE_MIB: u32 = 384;

impl Config {
    /// Compute `(base_mib, max_mib)` from an optional `--mem` cap and host total RAM.
    /// With no `--mem`, the VM can grow dynamically up to all host RAM; with `--mem N`,
    /// `N` is the hard ceiling while boot RAM stays small (`<= ELASTIC_BASE_MIB`).
    pub fn elastic_limits(cap_mib: Option<u32>, host_ram_mib: u64) -> Result<(u32, u32)> {
        let cap = match cap_mib {
            Some(n) => n,
            None => {
                if host_ram_mib == 0 {
                    bail!("cannot determine host memory for software VM; pass --mem");
                }
                (host_ram_mib & !1).clamp(128, 1_048_576) as u32
            }
        };
        if !(128..=1_048_576).contains(&cap) {
            bail!("software --mem must be 128..1048576 MiB");
        }
        if cap <= ELASTIC_BASE_MIB {
            return Ok((cap, cap));
        }
        let base = ELASTIC_BASE_MIB - ((cap - ELASTIC_BASE_MIB) % 2);
        Ok((base, cap))
    }

    pub fn effective_max_mib(&self) -> u32 {
        self.max_mib.max(self.mem_mib)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_limits()?;
        if let Some(provider) = &self.parent_kvm {
            if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
                bail!("the parent KVM provider requires x86_64 or aarch64");
            }
            if !(1..=self.mem_mib.min(256)).contains(&provider.child_mem_mib) {
                bail!("--parent-kvm-mem must be 1..{} MiB", self.mem_mib.min(256));
            }
            if !matches!(provider.engine.as_str(), "auto" | "tcg" | "kvm") {
                bail!("--parent-kvm-engine must be auto, tcg, or kvm");
            }
            if cfg!(target_arch = "aarch64") && provider.engine == "kvm" && !provider.bundle.join("native-worker").is_file() {
                bail!("ARM parent KVM bundle has no native-worker: {}", provider.bundle.display());
            }
            if !provider.bundle.join("flexvm-pvkvm.img").is_file() {
                bail!("parent KVM bundle has no flexvm-pvkvm.img: {}", provider.bundle.display());
            }
        }
        if !self.kernel.is_file() {
            bail!("software kernel is not a file: {}", self.kernel.display());
        }
        Ok(())
    }

    fn validate_limits(&self) -> Result<()> {
        if !(128..=1_048_576).contains(&self.mem_mib) {
            bail!("software --mem must be 128..1048576 MiB");
        }
        if self.max_mib != 0 && self.max_mib < self.mem_mib {
            bail!("software max memory ({}) must be at least --mem ({})", self.max_mib, self.mem_mib);
        }
        let max_mib = self.effective_max_mib();
        if max_mib > 1_048_576 {
            bail!("software max memory must be at most 1048576 MiB");
        }
        if max_mib > self.mem_mib && !(max_mib - self.mem_mib).is_multiple_of(2) {
            bail!("software elastic hotplug size (max memory - --mem) must be a multiple of 2 MiB");
        }
        if !(1..=256).contains(&self.vcpus) {
            bail!("software --vcpus must be 1..256");
        }
        if self.boot_timeout.is_zero() || self.boot_timeout > Duration::from_secs(3600) {
            bail!("software --timeout must be 1..3600 seconds (boot only)");
        }
        Ok(())
    }

    fn command(&self, engine: &Path, kernel: &Path, rootfs: &Path, endpoints: &Endpoints<'_>, network: Network, disks: &[(&str, PathBuf)]) -> Result<Command> {
        let arch = std::env::consts::ARCH;
        let (board, cpu, console, block, vsock, nic, balloon) = match arch {
            // TCG implements AMD SVM: the ordinary guest Linux KVM driver
            // supplies the ABI without a host KVM device. Enforce support
            // instead of silently losing guest virtualization capabilities.
            "x86_64" => {
                let cpu = if self.parent_kvm.is_some() { "max,vmx=off,svm=off" } else { "max,svm=on,npt=on,enforce=on" };
                ("q35", cpu, "ttyS0", "virtio-blk-pci", "vhost-user-vsock-pci", "virtio-net-pci", "virtio-balloon-pci")
            }
            "aarch64" => {
                let board = if self.parent_kvm.is_some() { "virt,gic-version=3" } else { "virt,virtualization=on,gic-version=3" };
                (board, "cortex-a72", "ttyAMA0", "virtio-blk-device", "vhost-user-vsock-device", "virtio-net-device", "virtio-balloon-device")
            }
            _ => bail!("software execution is not implemented for {arch}"),
        };
        let ram = if self.parent_kvm.is_some() { "outer-ram" } else { "ram" };
        let max_mib = self.effective_max_mib();
        let hotplug_mib = if self.parent_kvm.is_some() { 0 } else { max_mib - self.mem_mib };
        // QEMU x86_64 TCG defaults to 40-bit physical addresses (1 TiB), which
        // is too small once the 32-bit PCI hole and hotplug device-memory
        // alignment push guest RAM above 1 TiB. Request 42-bit physical
        // addresses (4 TiB) for elastic or >512 GiB x86_64 VMs while keeping
        // the legacy CPU profile unchanged for smaller fixed-memory checkpoints.
        let cpu = if arch == "x86_64" && self.parent_kvm.is_none() && (hotplug_mib > 0 || max_mib > 524_288) {
            "max,svm=on,npt=on,enforce=on,phys-bits=42"
        } else {
            cpu
        };
        let mut cmd = Command::new(engine);
        cmd.arg("-L").arg(endpoints.firmware);
        cmd.args(["-machine", &format!("{board},memory-backend={ram}"), "-accel", "tcg,thread=multi", "-cpu", cpu]);
        if hotplug_mib > 0 {
            cmd.args(["-m", &format!("size={}M,slots=1,maxmem={}M", self.mem_mib, max_mib), "-smp", &self.vcpus.to_string()]);
        } else {
            cmd.args(["-m", &self.mem_mib.to_string(), "-smp", &self.vcpus.to_string()]);
        }
        if self.parent_kvm.is_none() {
            cmd.args(["-object", &json!({"qom-type":"memory-backend-memfd", "id":"ram", "size":u64::from(self.mem_mib)<<20, "share":true}).to_string()]);
        }
        if hotplug_mib > 0 {
            cmd.args([
                "-object",
                &json!({"qom-type":"memory-backend-memfd", "id":"hotplug", "size":u64::from(hotplug_mib)<<20, "share":true, "reserve":false}).to_string(),
            ]);
            cmd.args(["-device", "virtio-mem-pci,id=vmem0,memdev=hotplug,requested-size=0,block-size=2M"]);
            cmd.args(["-device", &format!("{balloon},free-page-reporting=on")]);
        }
        cmd.args(["-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot"]);
        cmd.args(["-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]);
        let control_arg = if self.control == Control::Serial { " flexvm.control=serial" } else { "" };
        let hotplug_arg =
            if hotplug_mib > 0 { " memhp_default_state=online memory_hotplug.online_policy=auto-movable memory_hotplug.auto_movable_ratio=2000" } else { "" };
        let kvm_arg = if self.parent_kvm.is_some() { " flexvm.kvm=parent" } else { "" };
        let tmpfs_mib = if hotplug_mib > 0 { max_mib } else { self.mem_mib };
        cmd.arg("-kernel").arg(kernel).args([
            "-append",
            &format!(
                "console={console} quiet panic=1 root=/dev/vda ro init=/sbin/flexvm-init flexvm.tmpfs_mib={}{}{}{}{}",
                tmpfs_mib,
                control_arg,
                hotplug_arg,
                network.kernel_arg(),
                kvm_arg,
            ),
        ]);
        // ARM virt auto-assigns MMIO buses in reverse enumeration order. With managed
        // disks, bind the root and each disk to the buses Linux enumerates first.
        let root_bus = if arch == "aarch64" && !disks.is_empty() { ",bus=virtio-mmio-bus.0" } else { "" };
        cmd.args([
            "-blockdev",
            &json!({"driver":"raw", "node-name":"root", "read-only":true, "file":{"driver":"file", "filename":rootfs}}).to_string(),
            "-device",
            &format!("{block},drive=root{root_bus}"),
        ]);
        for (index, (id, path)) in disks.iter().enumerate() {
            let node = format!("managed-{index}");
            let mut device = format!("{block},drive={node},serial={}", &id[..20]);
            if arch == "aarch64" {
                device.push_str(&format!(",bus=virtio-mmio-bus.{}", index + 1));
            }
            cmd.args(["-blockdev", &json!({"driver":"raw", "node-name":node, "file":{"driver":"file", "filename":path}}).to_string(), "-device", &device]);
        }
        // Private short socket paths contain no keyval separators.
        if self.control == Control::Vsock {
            cmd.args(["-chardev", &format!("socket,id=vsock,path={}", endpoints.backend.display()), "-device", &format!("{vsock},chardev=vsock")]);
        } else {
            let device = if arch == "x86_64" { "virtio-serial-pci" } else { "virtio-serial-device" };
            cmd.args(["-device", &format!("{device},id=controlbus")]);
            cmd.args(["-chardev", &format!("socket,id=control,path={},server=on,wait=off", endpoints.control.display())]);
            cmd.args(["-device", &format!("virtserialport,bus=controlbus.0,chardev=control,name={}", control::PORT_NAME)]);
        }
        cmd.args(["-netdev", network.netdev(), "-device", &format!("{nic},netdev=net")]);
        cmd.args(["-qmp", &format!("unix:{},server=on,wait=off", endpoints.api.display())]);
        Ok(cmd)
    }

    pub fn profile(&self) -> Result<software_state::Profile> {
        self.profile_for(Network::Private, &[])
    }

    pub fn profiles(&self) -> Result<[software_state::Profile; 2]> {
        Ok([self.profile()?, self.profile_for(Network::Legacy, &[])?])
    }

    fn disk_profile<'a>(ids: impl Iterator<Item = &'a str>) -> Vec<(&'a str, PathBuf)> {
        ids.map(|id| (id, PathBuf::from(format!("@disk:{id}")))).collect()
    }

    pub fn profiles_for_disk_ids<'a>(&self, ids: impl Iterator<Item = &'a str>) -> Result<[software_state::Profile; 2]> {
        let disks = Self::disk_profile(ids);
        Ok([self.profile_for(Network::Private, &disks)?, self.profile_for(Network::Legacy, &disks)?])
    }

    fn profile_for(&self, network: Network, disks: &[(&str, PathBuf)]) -> Result<software_state::Profile> {
        let endpoints =
            Endpoints { api: Path::new("@qmp"), control: Path::new("@control"), backend: Path::new("@vsock-backend"), firmware: Path::new("@firmware") };
        let command = self.command(Path::new("@engine"), Path::new("@kernel"), Path::new("@rootfs"), &endpoints, network, disks)?;
        Ok(software_state::Profile {
            architecture: std::env::consts::ARCH.into(),
            arguments: command
                .get_args()
                .map(|arg| arg.to_str().map(str::to_owned).ok_or_else(|| "software profile contains a non-UTF8 argument".into()))
                .collect::<Result<_>>()?,
        })
    }

    pub fn boot(&self, rootfs: &Path, processes: Arc<Processes>, disks: Vec<volume::Writer>) -> Result<Machine> {
        let inputs = software_state::Inputs::open(&self.qemu, &self.kernel, rootfs)?;
        self.launch(inputs, processes, None, Network::Private, disks)
    }

    pub fn boot_with_kernel(&self, rootfs: &Path, processes: Arc<Processes>, kernel: software_state::Input, disks: Vec<volume::Writer>) -> Result<Machine> {
        let inputs = software_state::Inputs::with_kernel(&self.qemu, kernel, rootfs)?;
        self.launch(inputs, processes, None, Network::Private, disks)
    }

    /// Load state into a fresh engine, with CPUs paused and public admission closed.
    pub fn restore(&self, verified: software_state::Verified, processes: Arc<Processes>, disks: Vec<volume::Writer>) -> Result<Machine> {
        match (&self.parent_kvm, &verified.manifest.parent) {
            (None, None) => {}
            (Some(config), Some(parent)) if config.engine == (if parent.native { "kvm" } else { "tcg" }) && config.child_mem_mib == parent.child_memory_mib => {
            }
            _ => bail!("software restore requires the captured parent KVM configuration"),
        }
        if self.control != Control::Serial {
            bail!("software restore requires serial control");
        }
        let [private, legacy] = self.profiles_for_disk_ids(disks.iter().map(|disk| disk.id.as_str()))?;
        let network = if private == verified.manifest.profile {
            Network::Private
        } else if legacy == verified.manifest.profile {
            Network::Legacy
        } else {
            bail!("software restore configuration changed after artifact validation");
        };
        verified.state.unchanged()?;
        if let Some(parent) = &verified.parent {
            parent.worker.unchanged()?;
            parent.broker.unchanged()?;
        }
        let incoming = Incoming { state: &verified.state.file, version: &verified.manifest.engine_version, parent: verified.parent.as_ref() };
        let machine = self
            .launch(verified.inputs, processes, Some(incoming), network, disks)
            .map_err(|error| format!("software incoming engine load failed: {error}"))?;
        verified.state.unchanged()?;
        if let Some(parent) = &verified.parent {
            parent.worker.unchanged()?;
            parent.broker.unchanged()?;
        }
        Ok(machine)
    }

    fn launch(
        &self,
        inputs: software_state::Inputs,
        processes: Arc<Processes>,
        incoming: Option<Incoming<'_>>,
        network: Network,
        disks: Vec<volume::Writer>,
    ) -> Result<Machine> {
        // Restore uses pinned artifacts and does not require the original input paths.
        self.validate_limits()?;
        inputs.engine.unchanged()?;
        inputs.kernel.unchanged()?;
        inputs.rootfs.unchanged()?;
        let disk_profile = Self::disk_profile(disks.iter().map(|disk| disk.id.as_str()));
        let profile = self.profile_for(network, &disk_profile)?;
        let root = SocketRoot::software()?;
        *processes.runtime.lock().unwrap() = Some(Arc::downgrade(&root));
        let sockets = root.allocate()?;
        let logs = root.dir.join("logs");
        fs::create_dir(&logs)?;
        let kernel = PathBuf::from(format!("/proc/self/fd/{}", inputs.kernel.file.as_raw_fd()));
        let rootfs = PathBuf::from(format!("/proc/self/fd/{}", inputs.rootfs.file.as_raw_fd()));
        let engine_fd = inputs.engine.file.as_raw_fd();
        let engine = PathBuf::from(format!("/proc/self/fd/{engine_fd}"));
        let mut inherited = vec![engine_fd, inputs.kernel.file.as_raw_fd(), inputs.rootfs.file.as_raw_fd()];
        let mut machine = Machine {
            inputs: Some(inputs),
            disks,
            profile,
            network,
            engine_version: Value::Null,
            capture: Mutex::default(),
            processes,
            sockets,
            logs,
            transport: self.control,
            control: Mutex::new(None),
            parent_provider: self.parent_kvm.is_some(),
            parent_fence: None,
            parent_frontend: None,
            _native_worker: None,
            parent_memory_mib: self.parent_kvm.as_ref().map_or(0, |parent| parent.child_mem_mib),
        };
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
            let disks: Vec<_> = machine
                .disks
                .iter()
                .map(|disk| {
                    let fd = disk.file.as_raw_fd();
                    inherited.push(fd);
                    (disk.id.as_str(), PathBuf::from(format!("/proc/self/fd/{fd}")))
                })
                .collect();
            let mut cmd = self.command(&engine, &kernel, &rootfs, &endpoints, network, &disks)?;
            let saved_parent = incoming.as_ref().and_then(|state| state.parent);
            if incoming.is_some() && saved_parent.is_none() {
                cmd.args(["-incoming", "defer", "-S"]);
            }
            if let Some(provider) = &self.parent_kvm {
                if let Some(fds) = incoming.as_ref().and_then(Incoming::parent_fds) {
                    inherited.extend(fds);
                }
                let (parent_command, frontend, native_worker) = provider.command(cmd, &inherited, incoming.as_ref(), &root, self.mem_mib, endpoints.api)?;
                cmd = parent_command;
                machine.parent_frontend = Some(frontend);
                machine._native_worker = native_worker;
            }
            machine.processes.spawn_with_fds(&mut cmd, &machine.logs.join("qemu.log"), &inherited)?;
            while !machine.sockets.api.exists() {
                machine.processes.alive()?;
                remaining(deadline)?;
                std::thread::sleep(Duration::from_millis(10));
            }
            let parent_fence_path = root.dir.join("k/checkpoint");
            if machine.parent_provider && parent_fence_path.exists() {
                machine.parent_fence = Some(ParentFence { path: parent_fence_path, lease: Mutex::default() });
            }
            if saved_parent.is_some() {
                let fence = machine.parent_fence.as_ref().ok_or("parent KVM restore requires the checkpoint socket")?;
                // The broker owns the outer monitor until both emulators are restored.
                fence.acquire(b"ready", deadline)?;
            }
            let mut qmp = Qmp::connect(&machine.sockets.api, deadline)?;
            machine.engine_version = qmp.command("query-version", json!({}), &[])?;
            if let Some(incoming) = incoming {
                if machine.engine_version != *incoming.version {
                    bail!("software engine version differs from the captured profile");
                }
                if incoming.parent.is_none() {
                    qmp.command("getfd", json!({"fdname":"restore"}), &[incoming.state.as_raw_fd()])?;
                    qmp.command("migrate-incoming", json!({"uri":"fd:restore"}), &[])?;
                    machine.wait_migration(&mut qmp, deadline, true)?;
                }
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
                *machine.control.lock().unwrap() = Some(control::Client::connect(stream)?);
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
            let line = format!("START {} {}.{:09} {}", network.ip(), now.as_secs(), now.subsec_nanos(), network.dns());
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
            template::interrupted()?;
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
    pub fn ip(&self) -> std::net::Ipv4Addr {
        self.network.ip()
    }

    pub fn has_parent_fence(&self) -> bool {
        self.parent_fence.is_some()
    }

    pub fn checkpoint_supported(&self) -> Result<()> {
        if self.parent_provider && (self.parent_fence.is_none() || self.parent_frontend.is_none()) {
            bail!("parent-owned KVM requires a checkpoint-capable provider and frontend");
        }
        Ok(())
    }

    /// The caller owns the admission/CPU boundary and the output artifact. A
    /// failed export does not authorize source resume: cancel and verify first.
    pub fn save(&self, state: &File, deadline: Instant) -> Result<()> {
        if self.parent_provider {
            bail!("parent-owned KVM requires a hierarchy checkpoint");
        }
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
            if let Some(fence) = &self.parent_fence {
                fence.rollback(deadline)?;
            }
            qmp.command("cont", json!({}), &[])?;
            let status = qmp.command("query-status", json!({}), &[])?;
            if status["running"] != true || status["status"] != "running" {
                bail!("software source did not resume: {status}");
            }
            if let Some(fence) = &self.parent_fence {
                fence.lease.lock().unwrap().take();
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

    pub fn capture_pending(&self) -> bool {
        *self.capture.lock().unwrap() != Capture::None
    }

    pub fn checkpoint(
        &self,
        mut staging: software_state::Staging,
        destination: &Path,
        mut manifest: software_state::Manifest,
        previous: Option<&software_state::Consumed>,
        deadline: Instant,
    ) -> Result<software_state::Published> {
        if manifest.source_owner != crate::host::Ident::me() || manifest.source_engine != self.processes.engine_ident()? {
            bail!("software capture metadata does not identify this engine and owner");
        }
        self.checkpoint_supported()?;
        if let (Some(fence), Some(frontend)) = (&self.parent_fence, &self.parent_frontend) {
            // Refusal here leaves the existing pause lease intact. Once save
            // is sent, only explicit rollback can authorize source execution.
            let native = fence.check_save(deadline)?;
            let outer = staging.state.as_raw_fd();
            let parent = staging.prepare_parent(frontend, self.parent_memory_mib, native)?;
            let fds = [outer, parent.worker.as_raw_fd(), parent.broker.as_raw_fd()];
            let mut capture = self.capture.lock().unwrap();
            if *capture != Capture::None {
                bail!("software state capture is unresolved");
            }
            *capture = Capture::Uncertain;
            fence.save(&fds, deadline)?;
            *capture = Capture::Exported;
        } else {
            self.save(&staging.state, deadline)?;
        }
        // QEMU has paused vCPUs and drained its block layer at the
        // checkpoint boundary. Keep the writer leases through publication.
        manifest.disks = staging.capture_disks(&self.disks)?;
        manifest.profile = self.profile.clone();
        manifest.engine_version = self.engine_version.clone();
        let inputs = self.inputs.as_ref().ok_or("software engine has no pinned inputs")?;
        match previous {
            Some(previous) => staging.replace(destination, inputs, manifest, previous),
            None => staging.commit(destination, inputs, manifest),
        }
    }

    pub fn retire(&self, published: &software_state::Published) -> Result<()> {
        if published.manifest.source_engine != self.processes.engine_ident()? {
            bail!("software checkpoint belongs to another engine");
        }
        self.processes.stop();
        published.retire()
    }

    pub fn disconnect_control(&self) {
        let previous = self.control.lock().unwrap().take();
        drop(previous);
    }

    pub fn reconnect_control(&self, deadline: Instant) -> Result<()> {
        let mut control = self.control.lock().unwrap();
        if control.is_none() {
            let stream = util::connect_unix(&self.sockets.vsock, remaining(deadline)?)?;
            *control = Some(control::Client::connect(stream)?);
        }
        Ok(())
    }

    pub fn checkpoint_capable(&self, deadline: Instant) -> Result<()> {
        if self.transport != Control::Serial || self.message("BARRIER 1 TRANSPORT", deadline)? != b"ok BARRIER 1 TRANSPORT 1" {
            bail!("software checkpoint requires serial transport reset support; rebuild the guest agent");
        }
        Ok(())
    }

    /// Close admission, discard both old transport parsers, then stop CPUs. The
    /// reset marker is bound to this barrier, so log rotation or an earlier reset
    /// cannot be mistaken for this acknowledged transition.
    pub fn quiesce_control(&self, generation: u64, epoch: u64, sequence: u64, deadline: Instant) -> Result<()> {
        let request = format!("BARRIER 1 QUIESCE {generation} {epoch} {sequence}");
        let expected = format!("ok BARRIER 1 QUIESCED {generation} {sequence}");
        if self.message(&request, deadline)? != expected.as_bytes() {
            bail!("software guest did not acknowledge its request barrier");
        }
        self.disconnect_control();
        self.wait_control_reset(generation, sequence, deadline)?;
        self.switch("stop", deadline)
    }

    pub fn wait_control_reset(&self, generation: u64, sequence: u64, deadline: Instant) -> Result<()> {
        let expected = format!("flexvm-init: serial control ready barrier {generation} {sequence}");
        loop {
            self.processes.alive()?;
            if remaining(deadline).is_err() {
                bail!("software serial transport did not acknowledge barrier {generation}/{sequence} reset\n{}", self.diagnostics());
            }
            let mut console = Vec::new();
            for name in ["qemu.log.1", "qemu.log"] {
                match fs::read(self.logs.join(name)) {
                    Ok(bytes) => console.extend(bytes),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if String::from_utf8_lossy(&console).lines().any(|line| line.trim_end() == expected) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn resume_admission(&self, generation: u64, epoch: u64, saved_generation: u64, sequence: u64, deadline: Instant) -> Result<()> {
        self.set_admission(generation, epoch, saved_generation, sequence, true, deadline)
            .map_err(|error| format!("software request-admission resume failed: {error}\n{}", self.diagnostics()).into())
    }

    pub fn abort_admission(&self, generation: u64, epoch: u64, saved_generation: u64, sequence: u64, deadline: Instant) -> Result<()> {
        self.set_admission(generation, epoch, saved_generation, sequence, false, deadline)
    }

    fn set_admission(&self, generation: u64, epoch: u64, saved_generation: u64, sequence: u64, correct_clock: bool, deadline: Instant) -> Result<()> {
        self.reconnect_control(deadline)?;
        if self.message(&format!("FENCE {generation} {epoch}"), deadline).map_err(|error| format!("owner fence transport: {error}"))?
            != format!("ok {generation}").as_bytes()
        {
            bail!("software guest rejected its owner fence");
        }
        if correct_clock {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let clock = format!("BARRIER 1 MAINT {generation} {epoch} CLOCK {}.{:09}", now.as_secs(), now.subsec_nanos());
            if !self.message(&clock, deadline).map_err(|error| format!("clock maintenance transport: {error}"))?.starts_with(b"ok ") {
                bail!("software guest rejected clock maintenance");
            }
        }
        let request = format!("BARRIER 1 RESUME {generation} {epoch} {saved_generation} {sequence}");
        if self.message(&request, deadline).map_err(|error| format!("barrier resume transport: {error}"))?
            != format!("ok BARRIER 1 RESUMED {saved_generation} {sequence}").as_bytes()
        {
            bail!("software guest did not resume request admission");
        }
        Ok(())
    }

    /// vhost-device-vsock 0.3 reads ahead and discards bytes after CONNECT.
    /// Wait for its OK before writing the agent command; Firecracker keeps its
    /// existing pipelined handshake and does not pay this extra round trip.
    pub fn request(&self, line: &str, deadline: Instant) -> Result<BufReader<std::os::unix::net::UnixStream>> {
        let stream = match self.transport {
            Control::Serial => self.control.lock().unwrap().as_ref().ok_or("software serial control is disconnected")?.open(deadline)?,
            Control::Vsock => util::connect_unix(&self.sockets.vsock, remaining(deadline)?)?,
        };
        let mut r = BufReader::with_capacity(1, stream);
        if self.transport == Control::Vsock {
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

    pub fn meminfo(&self, deadline: Instant) -> Result<(u64, u64)> {
        let reply = self.message("MEMINFO", deadline)?;
        parse_meminfo(&String::from_utf8_lossy(&reply))
    }

    pub fn set_virtio_mem(&self, bytes: u64, deadline: Instant) -> Result<()> {
        let mut qmp = Qmp::connect(&self.sockets.api, deadline)?;
        qmp.command("qom-set", json!({"path": "vmem0", "property": "requested-size", "value": bytes}), &[])?;
        Ok(())
    }

    pub fn virtio_mem_size(&self, deadline: Instant) -> Result<u64> {
        let mut qmp = Qmp::connect(&self.sockets.api, deadline)?;
        let reply = qmp.command("qom-get", json!({"path": "vmem0", "property": "size"}), &[])?;
        reply.as_u64().ok_or_else(|| format!("unexpected qom-get virtio-mem size: {reply}").into())
    }

    pub fn switch(&self, command: &str, deadline: Instant) -> Result<()> {
        let capture = self.capture.lock().unwrap();
        if *capture != Capture::None {
            bail!("software state capture must be resolved before changing CPU state");
        }
        if let Some(fence) = self.parent_fence.as_ref().filter(|_| command == "stop") {
            // Keep ownership through an uncertain QMP stop. The caller can
            // still recover with a confirmed resume on this same lease.
            fence.acquire(b"freeze", deadline)?;
        }
        let mut qmp = Qmp::connect(&self.sockets.api, deadline)?;
        qmp.command(command, json!({}), &[])?;
        let state = qmp.command("query-status", json!({}), &[])?;
        let expected = if command == "stop" { "paused" } else { "running" };
        if state["status"] != expected {
            bail!("QMP did not enter {expected}: {state}");
        }
        if let Some(fence) = self.parent_fence.as_ref().filter(|_| command == "cont") {
            fence.thaw(deadline)?;
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

    pub fn finish_exec_at(
        &self,
        reader: &mut BufReader<UnixStream>,
        id: &str,
        offset: &mut u64,
        out: impl FnMut(u8, &[u8]) -> Result<()>,
    ) -> std::result::Result<i32, guest::OutputError> {
        guest::exec_output_at(&mut Watched { reader, processes: &self.processes }, id, offset, out)
    }

    pub fn start_distro(&self, deadline: Instant) -> Result<()> {
        if self.message("APP", deadline)? != b"ok 1" {
            bail!("software distro init did not accept its cold boot gate");
        }
        self.wait_distro_ready(deadline)
    }

    pub fn wait_distro_ready(&self, deadline: Instant) -> Result<()> {
        loop {
            self.processes.alive()?;
            let left = remaining(deadline)?;
            let reply = self.message("APPSTATUS", Instant::now() + left.min(guest::TIMEOUT))?;
            match reply.as_slice() {
                b"running 1" => return Ok(()),
                b"starting 1" => std::thread::sleep(left.min(Duration::from_millis(50))),
                _ => bail!("software distro init failed to start: {}", String::from_utf8_lossy(&reply)),
            }
        }
    }

    /// A distro follows the engine's real lifetime, not a synthetic exec session.
    pub fn distro_exit(&self) -> Result<Option<i32>> {
        let Some(status) = self.processes.engine_status()? else {
            self.processes.alive()?;
            return Ok(None);
        };
        let mut console = Vec::new();
        for name in ["qemu.log.1", "qemu.log"] {
            match fs::read(self.logs.join(name)) {
                Ok(bytes) => console.extend(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        if status.success() && crate::fc::kernel_shutdown(&String::from_utf8_lossy(&console)).is_some() {
            return Ok(Some(0));
        }
        bail!("software distro engine exited without a completed guest power-off or reboot: {status}; {}", self.diagnostics())
    }

    pub fn exec(&self, argv: Vec<String>, out: impl FnMut(u8, &[u8]) -> Result<()>) -> Result<i32> {
        let (id, mut reader) = self.start_exec(argv)?;
        self.finish_exec(&mut reader, &id, out)
    }

    pub(crate) fn diagnostics(&self) -> String {
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

fn parse_meminfo(reply: &str) -> Result<(u64, u64)> {
    let mut parts = reply.split_whitespace();
    if parts.next() != Some("ok") {
        bail!("guest MEMINFO failed: {reply}");
    }
    let avail = parts.next().and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| format!("bad MEMINFO available: {reply}"))?;
    let total = parts.next().and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| format!("bad MEMINFO total: {reply}"))?;
    if parts.next().is_some() {
        bail!("unexpected trailing MEMINFO fields: {reply}");
    }
    Ok((avail, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn new_network_is_private_and_legacy_profiles_keep_the_original_command() {
        let config = Config {
            control: Control::Serial,
            kernel: PathBuf::new(),
            qemu: String::new(),
            vsock_backend: String::new(),
            mem_mib: 512,
            max_mib: 512,
            vcpus: 1,
            boot_timeout: Duration::from_secs(120),
            parent_kvm: None,
        };
        let [private, legacy] = config.profiles().unwrap();
        assert_eq!(private, config.profile().unwrap());
        assert_eq!(Network::from_profile(&private), Some(Network::Private));
        assert_eq!(Network::from_profile(&legacy), Some(Network::Legacy));
        let kernel_args = |profile: &software_state::Profile| profile.arguments.windows(2).find(|args| args[0] == "-append").unwrap()[1].clone();
        assert!(kernel_args(&private).ends_with(" flexvm.gateway4=10.0.2.2"));
        assert!(!kernel_args(&legacy).contains("flexvm.gateway4="));
        let mut unknown = private.clone();
        let position = unknown.arguments.iter().position(|arg| arg == "-netdev").unwrap() + 1;
        unknown.arguments[position].push_str(",hostfwd=tcp::22-:22");
        assert_eq!(Network::from_profile(&unknown), None);
    }

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
        let (rootfs, meta, _reservation, _use_lock) = crate::image::prepare(&dir.join("images"), None, &options, None).unwrap();
        let mut config = Config {
            control: Control::Serial,
            kernel: kernel.into(),
            qemu: std::env::var("FLEXVM_SOFTWARE_TEST_QEMU").unwrap_or_else(|_| format!("qemu-system-{}", std::env::consts::ARCH)),
            vsock_backend: String::new(),
            mem_mib: 512,
            max_mib: 512,
            vcpus: 1,
            boot_timeout: Duration::from_secs(60),
            parent_kvm: None,
        };
        let source = Arc::new(Processes::default());
        let machine = config.boot(&rootfs, source.clone(), Vec::new()).unwrap();
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
        machine.checkpoint_capable(deadline).unwrap();
        drop(output);
        machine.quiesce_control(1, 42, 1, deadline).unwrap();
        let staging = software_state::Staging::new(&dir).unwrap();
        machine.save(&staging.state, deadline).unwrap();
        assert!(machine.switch("cont", deadline).unwrap_err().to_string().contains("capture must be resolved"));
        let blank = software_state::Artifact { bytes: 0, sha256: String::new() };
        let manifest = software_state::Manifest {
            format: 1,
            backend: "qemu-tcg".into(),
            vm_id: util::random_hex(16).unwrap(),
            snapshot_id: util::random_hex(16).unwrap(),
            identity_generation: 1,
            memory_mib: 512,
            max_memory_mib: None,
            plugged_mib: 0,
            vcpus: 1,
            paused: false,
            terminal: true,
            host_id: "00000000000000000000000000000000".into(),
            source_owner: crate::host::Ident::me(),
            source_engine: source.engine_ident().unwrap(),
            owner_generation: 1,
            saved_epoch: 42,
            barrier_generation: 1,
            barrier_sequence: 1,
            profile: machine.profile.clone(),
            engine_version: machine.engine_version.clone(),
            engine: blank.clone(),
            kernel: blank.clone(),
            rootfs: blank.clone(),
            state: blank,
            firmware: std::collections::BTreeMap::new(),
            parent: None,
            disks: Vec::new(),
            main: software_state::Main::App(software_state::Session { id: id.clone(), offset: 0, claim: 0 }),
            image: meta,
        };
        let checkpoint = dir.join("checkpoint");
        let published = staging.commit(&checkpoint, machine.inputs.as_ref().unwrap(), manifest).unwrap();
        let old_engine = source.engine_ident().unwrap();
        source.stop();
        published.retire().unwrap();
        drop(machine);
        assert!(!old_engine.alive());
        let verified = software_state::open(&checkpoint, config.profile().unwrap()).unwrap();
        fs::rename(&checkpoint, dir.join("saved-artifacts")).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&checkpoint).unwrap();
        config.kernel = PathBuf::from("/missing-original-kernel");
        config.qemu = "/missing-original-engine".into();
        let target = Arc::new(Processes::default());
        let machine = config.restore(verified, target, Vec::new()).unwrap();
        machine.switch("cont", deadline).unwrap();
        machine.reconnect_control(deadline).unwrap();
        assert_eq!(machine.message("PING", deadline).unwrap(), b"pong");
        assert_eq!(machine.message("FENCE 2 84", deadline).unwrap(), b"ok 2");
        assert_ne!(machine.message("FENCE 1 42", deadline).unwrap(), b"ok 1");
        assert_ne!(machine.message("BARRIER 1 RESUME 2 84 1 99", deadline).unwrap(), b"ok BARRIER 1 RESUMED 1 99");
        machine.resume_admission(2, 84, 1, 1, deadline).unwrap();
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
            disks: Vec::new(),
            profile: software_state::Profile { architecture: std::env::consts::ARCH.into(), arguments: Vec::new() },
            network: Network::Private,
            engine_version: Value::Null,
            capture: Mutex::default(),
            processes: Arc::new(Processes::default()),
            sockets,
            logs,
            transport: Control::Vsock,
            control: Mutex::new(None),
            parent_provider: false,
            parent_fence: None,
            parent_frontend: None,
            _native_worker: None,
            parent_memory_mib: 0,
        }
    }

    #[test]
    fn transport_reset_handles_rotated_split_and_non_utf8_console_lines() {
        let machine = machine();
        fs::write(machine.logs.join("qemu.log.1"), b"\xff\nflexvm-init: serial control ready barrier 8 ").unwrap();
        fs::write(machine.logs.join("qemu.log"), b"3\r\n").unwrap();
        machine.wait_control_reset(8, 3, Instant::now() + Duration::from_secs(1)).unwrap();
        fs::write(machine.logs.join("qemu.log.1"), b"\xff\nflexvm-init: serial control ready barrier 8 3\n").unwrap();
        fs::remove_file(machine.logs.join("qemu.log")).unwrap();
        machine.wait_control_reset(8, 3, Instant::now() + Duration::from_secs(1)).unwrap();
        assert!(machine.wait_control_reset(8, 4, Instant::now() + Duration::from_millis(20)).is_err(), "an earlier barrier cannot acknowledge the next reset");
    }

    #[test]
    fn distro_poweroff_requires_actual_engine_exit_and_drained_console() {
        let machine = machine();
        let gate = machine.logs.join("exit-gate");
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf '[    1.0] reboot: Power down\n'; while [ ! -f \"$1\" ]; do sleep .01; done", "sh"]).arg(&gate);
        machine.processes.spawn(&mut cmd, &machine.logs.join("qemu.log")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fs::read_to_string(machine.logs.join("qemu.log")).unwrap_or_default().contains("Power down") {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(machine.distro_exit().unwrap(), None, "a live console cannot terminate or complete a VM");
        machine.processes.alive().unwrap();
        fs::write(gate, b"exit").unwrap();
        while machine.distro_exit().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(machine.distro_exit().unwrap(), Some(0));
    }

    #[test]
    fn distro_reboot_requires_actual_engine_exit_and_drained_console() {
        let machine = machine();
        machine.processes.spawn(Command::new("sh").args(["-c", "printf '[    1.0] reboot: Restarting system\n'"]), &machine.logs.join("qemu.log")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while machine.distro_exit().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(machine.distro_exit().unwrap(), Some(0));
    }

    #[test]
    fn distro_exit_rejects_panics_and_failed_engines() {
        for script in ["printf 'Kernel panic - not syncing: fatal\n[    1.0] reboot: Power down\n'", "printf '[    1.0] reboot: Power down\n'; exit 7"] {
            let machine = machine();
            machine.processes.spawn(Command::new("sh").args(["-c", script]), &machine.logs.join("qemu.log")).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while machine.distro_exit().is_ok() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
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
        assert!(processes.children.lock().unwrap().is_empty());
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

    #[test]
    fn elastic_memory_config_adds_virtio_mem_balloon_and_hotplug_args() {
        let mut config = Config {
            control: Control::Serial,
            kernel: PathBuf::new(),
            qemu: String::new(),
            vsock_backend: String::new(),
            mem_mib: 512,
            max_mib: 2048,
            vcpus: 1,
            boot_timeout: Duration::from_secs(120),
            parent_kvm: None,
        };
        config.validate_limits().unwrap();
        let profile = config.profile().unwrap();
        let m_arg = profile.arguments.windows(2).find(|args| args[0] == "-m").unwrap()[1].as_str();
        assert_eq!(m_arg, "size=512M,slots=1,maxmem=2048M");
        let hotplug_obj: Value = profile
            .arguments
            .windows(2)
            .filter(|args| args[0] == "-object")
            .filter_map(|args| serde_json::from_str::<Value>(&args[1]).ok())
            .find(|obj| obj["id"] == "hotplug")
            .unwrap();
        assert_eq!(hotplug_obj["qom-type"], "memory-backend-memfd");
        assert_eq!(hotplug_obj["size"], json!(1536u64 << 20));
        assert_eq!(hotplug_obj["share"], json!(true));
        assert_eq!(hotplug_obj["reserve"], json!(false));
        assert!(profile.arguments.iter().any(|a| a.contains("virtio-mem-pci,id=vmem0,memdev=hotplug,requested-size=0,block-size=2M")));
        assert!(profile.arguments.iter().any(|a| a.contains("free-page-reporting=on")));
        let append = profile.arguments.windows(2).find(|args| args[0] == "-append").unwrap()[1].as_str();
        assert!(append.contains("flexvm.tmpfs_mib=2048"), "{append}");
        assert!(append.contains("memhp_default_state=online"), "{append}");

        if cfg!(target_arch = "x86_64") {
            let make_config = |mem_mib, max_mib| Config {
                control: Control::Serial,
                kernel: PathBuf::new(),
                qemu: String::new(),
                vsock_backend: String::new(),
                mem_mib,
                max_mib,
                vcpus: 1,
                boot_timeout: Duration::from_secs(120),
                parent_kvm: None,
            };
            let cpu_arg = |cfg: &Config| cfg.profile().unwrap().arguments.windows(2).find(|args| args[0] == "-cpu").unwrap()[1].clone();
            assert_eq!(cpu_arg(&config), "max,svm=on,npt=on,enforce=on,phys-bits=42");

            let one_tib_elastic = make_config(ELASTIC_BASE_MIB, 1_048_576);
            one_tib_elastic.validate_limits().unwrap();
            assert_eq!(cpu_arg(&one_tib_elastic), "max,svm=on,npt=on,enforce=on,phys-bits=42");

            let one_tib_fixed = make_config(1_048_576, 1_048_576);
            one_tib_fixed.validate_limits().unwrap();
            assert_eq!(cpu_arg(&one_tib_fixed), "max,svm=on,npt=on,enforce=on,phys-bits=42");

            let small_fixed = make_config(512, 512);
            assert_eq!(cpu_arg(&small_fixed), "max,svm=on,npt=on,enforce=on");
        }

        config.max_mib = 256;
        let err = config.validate_limits().unwrap_err().to_string();
        assert!(err.contains("software max memory"), "{err}");
        config.max_mib = 513;
        let err = config.validate_limits().unwrap_err().to_string();
        assert!(err.contains("max memory"), "{err}");
    }

    #[test]
    fn qmp_virtio_mem_resize_and_size_query_round_trip() {
        let machine = machine();
        let listener = UnixListener::bind(&machine.sockets.api).unwrap();
        let server = std::thread::spawn(move || {
            let mut reader = BufReader::new(qmp_peer(listener.try_clone().unwrap()));
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(req["execute"], "qom-set");
            assert_eq!(req["arguments"], json!({"path":"vmem0","property":"requested-size","value":256u64 << 20}));
            writeln!(reader.get_mut(), "{}", json!({"return":{},"id":req["id"]})).unwrap();

            let mut reader = BufReader::new(qmp_peer(listener));
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(req["execute"], "qom-get");
            assert_eq!(req["arguments"], json!({"path":"vmem0","property":"size"}));
            writeln!(reader.get_mut(), "{}", json!({"return":256u64 << 20,"id":req["id"]})).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        machine.set_virtio_mem(256 << 20, deadline).unwrap();
        assert_eq!(machine.virtio_mem_size(deadline).unwrap(), 256 << 20);
        server.join().unwrap();
    }

    #[test]
    fn parse_meminfo_accepts_valid_and_rejects_malformed() {
        assert_eq!(parse_meminfo("ok 123456 524288").unwrap(), (123456, 524288));
        for bad in ["error: boom", "ok 123", "ok x 524288", "ok 1 2 3"] {
            assert!(parse_meminfo(bad).is_err(), "{bad}");
        }
        assert_eq!(Config::elastic_limits(None, 49152).unwrap(), (ELASTIC_BASE_MIB, 49152));
        assert_eq!(Config::elastic_limits(Some(2048), 49152).unwrap(), (ELASTIC_BASE_MIB, 2048));
        assert_eq!(Config::elastic_limits(Some(256), 49152).unwrap(), (256, 256));
        assert_eq!(Config::elastic_limits(Some(513), 49152).unwrap(), (383, 513));
        assert!(Config::elastic_limits(Some(64), 49152).is_err());
        let err = Config::elastic_limits(None, 0).unwrap_err().to_string();
        assert!(err.contains("cannot determine host memory"), "{err}");
        assert_eq!(Config::elastic_limits(Some(512), 0).unwrap(), (ELASTIC_BASE_MIB, 512));
    }
}
