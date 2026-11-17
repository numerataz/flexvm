//! Software execution with QEMU TCG and a userspace virtio-vsock backend.
//!
//! This cold-boot path owns both processes. Its state is separate from Firecracker
//! templates/checkpoints; native QEMU vhost-user-vsock is not yet migratable.
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::host::{AddrClaim, Host, Ident};
use crate::net;
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
    Routed,
}

impl Network {
    fn netdev(self) -> &'static str {
        match self {
            Self::Private => "user,id=net,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15,ipv6=off",
            Self::Legacy => "user,id=net,net=169.254.0.0/16,host=169.254.1.1,dns=169.254.1.3,dhcpstart=169.254.1.2,ipv6=off",
            Self::Routed => "tap,id=net,fd=@tap,vhost=off",
        }
    }

    pub fn ip(self) -> Option<std::net::Ipv4Addr> {
        match self {
            Self::Private => Some(std::net::Ipv4Addr::new(10, 0, 2, 15)),
            Self::Legacy => Some(std::net::Ipv4Addr::new(169, 254, 1, 2)),
            Self::Routed => None,
        }
    }

    fn dns(self) -> &'static str {
        match self {
            Self::Private => "10.0.2.3",
            Self::Legacy => "169.254.1.3",
            Self::Routed => "",
        }
    }

    fn kernel_arg(self) -> &'static str {
        match self {
            Self::Private => " flexvm.gateway4=10.0.2.2",
            Self::Legacy | Self::Routed => "",
        }
    }

    /// Metadata only; execution still requires equality with a full locally built profile.
    pub fn from_profile(profile: &software_state::Profile) -> Option<Self> {
        let value = profile.arguments.windows(2).find(|args| args[0] == "-netdev")?.get(1)?;
        [Self::Private, Self::Legacy, Self::Routed].into_iter().find(|network| network.netdev() == value)
    }
}

pub struct Routed {
    tap: OwnedFd,
    index: u32,
    network: software_state::RoutedNetwork,
    dns: Vec<IpAddr>,
    host: Host,
    claim: Option<AddrClaim>,
    incoming: bool,
    keep: AtomicBool,
}

impl Routed {
    pub fn new(host: &Host, name: &str) -> Result<Self> {
        let config = host.config_now();
        let claim = {
            let lock = host.lock()?;
            host.claim_new_in(&lock, &config, name, None)?
        };
        let network = software_state::RoutedNetwork { address: config.vm_addr(claim.ip), generation: claim.gen, revision: Some(claim.rev) };
        Self::prepare(host, &config, claim, network, false, false)
    }

    pub fn restore(host: &Host, name: &str, network: software_state::RoutedNetwork) -> Result<Self> {
        let config = host.config_now();
        if config.vm_addr(network.address.v4) != network.address {
            bail!("software routed address no longer matches the host network");
        }
        let claim = {
            let lock = host.lock()?;
            let address = host.addr(&lock, network.address.v4)?;
            if address.holder.as_deref() != Some(name) || address.held != network.generation {
                bail!("software checkpoint no longer holds its routed address");
            }
            if network.revision.is_some_and(|revision| revision > address.rev) {
                bail!("software checkpoint's routed revision was never published here");
            }
            // The local software preparation has already rejected an active
            // outbound receipt. Any loan on this exact generation was aborted.
            if address.lent == Some(network.generation) {
                host.unlend(&lock, network.address.v4, network.generation)?;
            }
            host.claim_incoming(&lock, name, network.address.v4, network.generation, None)?
        };
        Self::prepare(host, &config, claim, network, false, true)
    }

    pub fn arrive(host: &Host, name: &str, network: software_state::RoutedNetwork, returning: bool) -> Result<Self> {
        let config = host.config_now();
        let ip = network.address.v4;
        let revision = network.revision.and_then(|previous| previous.checked_add(1)).ok_or("software routed transfer needs a valid revision")?;
        crate::listen::check_vm_ip(host, ip, &crate::listen::known_peers(host)?)?;
        if config.vm_addr(ip) != network.address {
            bail!("software transfer routed address does not match the destination network");
        }
        if !returning && config.range()?.allocatable(ip) {
            bail!("software transfer cannot take an address from the destination's own pool");
        }
        let claim = {
            let lock = host.lock()?;
            let address = host.addr(&lock, ip)?;
            if address.arriving.is_some()
                || address.leaving.is_some()
                || !address.current(network.generation)
                || (address.seen == network.generation && address.rev >= revision)
            {
                bail!("software transfer routed address was superseded or is moving");
            }
            if returning {
                if address.lent != Some(network.generation) || address.seen != network.generation {
                    bail!("software transfer return does not match this host's routed loan");
                }
                if let Some(previous) = address.holder.as_deref() {
                    let owner = address.holder_id.as_ref().ok_or("software transfer return has an unidentified previous address holder")?;
                    if address.held != network.generation || crate::host::PidFd::open(owner)?.is_some() {
                        bail!("software transfer return address still has a live holder");
                    }
                    host.release(&lock, ip, previous, Some(owner))?;
                }
            } else if address.holder.is_some() || address.lent.is_some() {
                bail!("software transfer routed address is already held");
            }
            host.claim_incoming(&lock, name, ip, network.generation, Some(revision))?
        };
        Self::prepare(host, &config, claim, network, true, false)
    }

    fn prepare(
        host: &Host,
        config: &crate::host::Config,
        claim: AddrClaim,
        network: software_state::RoutedNetwork,
        incoming: bool,
        keep: bool,
    ) -> Result<Self> {
        let owner = Ident::me();
        let alias = crate::host::tap_alias(&host.run, &owner);
        let tap = (|| {
            let (tap, name, index) = net::open_software_tap(&alias, &format!("fsw{:x}", owner.pid))?;
            net::neighbour(network.address, &name)?;
            Ok((tap, index))
        })();
        let (tap, index) = match tap {
            Ok(tap) => tap,
            Err(error) => {
                if keep {
                    claim.keep();
                }
                return Err(error);
            }
        };
        Ok(Self { tap, index, network, dns: config.guest_dns(), host: host.clone(), claim: Some(claim), incoming, keep: AtomicBool::new(keep) })
    }

    fn checkpoint(&self) -> Result<software_state::RoutedNetwork> {
        let claim = self.claim.as_ref().ok_or("software routed guest has no address claim")?;
        let lock = self.host.fence(claim.ip, claim.gen)?;
        let address = self.host.addr(&lock, claim.ip)?;
        if address.held != claim.gen || address.holder_id.as_ref() != Some(&Ident::me()) {
            bail!("software checkpoint no longer owns its routed address");
        }
        // A newly allocated address normally stays unsynced while its VM runs.
        self.host.sync_addr(&lock, claim.ip)?;
        Ok(software_state::RoutedNetwork { revision: Some(claim.rev), ..self.network })
    }

    fn publish(&self) -> Result<()> {
        let claim = self.claim.as_ref().ok_or("software routed guest has no address claim")?;
        let lock = self.host.fence(claim.ip, claim.gen)?;
        net::route(self.network.address, self.index)?;
        self.host.publish_live(&lock, claim.ip, claim.gen, claim.rev)?;
        if self.incoming {
            self.host.advance(&lock, claim.ip, claim.gen, claim.rev)?;
            self.host.unlend(&lock, claim.ip, claim.gen)?;
        }
        Ok(())
    }
}

impl Drop for Routed {
    fn drop(&mut self) {
        if !*self.keep.get_mut() {
            return;
        }
        if let Some(claim) = self.claim.take() {
            claim.keep();
        }
    }
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
    tap: Option<RawFd>,
}

pub struct Machine {
    inputs: Option<software_state::Inputs>,
    disks: Vec<volume::Writer>,
    profile: software_state::Profile,
    network: Network,
    routed: Option<Routed>,
    engine_version: Value,
    capture: Mutex<Capture>,
    processes: Arc<Processes>,
    sockets: Sockets,
    logs: PathBuf,
    transport: Control,
    control: Mutex<Option<control::Client>>,
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

    fn command(&self, engine: &Path, kernel: &Path, rootfs: &Path, endpoints: &Endpoints<'_>, network: Network, disks: &[(&str, PathBuf)]) -> Result<Command> {
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
            &format!(
                "console={console} quiet panic=1 root=/dev/vda ro init=/sbin/flexvm-init flexvm.tmpfs_mib={}{}{}",
                self.mem_mib,
                control_arg,
                network.kernel_arg()
            ),
        ]);
        cmd.args([
            "-blockdev",
            &json!({"driver":"raw", "node-name":"root", "read-only":true, "file":{"driver":"file", "filename":rootfs}}).to_string(),
            "-device",
            &format!("{block},drive=root"),
        ]);
        for (index, (id, path)) in disks.iter().enumerate() {
            let node = format!("managed-{index}");
            cmd.args([
                "-blockdev",
                &json!({"driver":"raw", "node-name":node, "file":{"driver":"file", "filename":path}}).to_string(),
                "-device",
                &format!("{block},drive={node},serial={}", &id[..20]),
            ]);
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
        match network {
            Network::Routed => {
                let backend = endpoints.tap.map_or_else(|| network.netdev().to_owned(), |fd| format!("tap,id=net,fd={fd},vhost=off"));
                cmd.args(["-netdev", &backend, "-device", &format!("{nic},netdev=net,mac={}", net::mac_string(&net::GUEST_MAC))]);
            }
            _ => {
                cmd.args(["-netdev", network.netdev(), "-device", &format!("{nic},netdev=net")]);
            }
        }
        cmd.args(["-qmp", &format!("unix:{},server=on,wait=off", endpoints.api.display())]);
        Ok(cmd)
    }

    #[cfg(test)]
    pub fn profile(&self) -> Result<software_state::Profile> {
        self.profile_for(Network::Private, &[])
    }

    #[cfg(test)]
    pub fn profiles(&self) -> Result<[software_state::Profile; 2]> {
        Ok([self.profile()?, self.profile_for(Network::Legacy, &[])?])
    }

    fn disk_profile<'a>(ids: impl Iterator<Item = &'a str>) -> Vec<(&'a str, PathBuf)> {
        ids.map(|id| (id, PathBuf::from(format!("@disk:{id}")))).collect()
    }

    pub fn profiles_for_disk_ids<'a>(&self, ids: impl Iterator<Item = &'a str>, routed: bool) -> Result<Vec<software_state::Profile>> {
        let disks = Self::disk_profile(ids);
        let networks: &[Network] = if routed { &[Network::Routed] } else { &[Network::Private, Network::Legacy] };
        networks.iter().map(|network| self.profile_for(*network, &disks)).collect()
    }

    fn profile_for(&self, network: Network, disks: &[(&str, PathBuf)]) -> Result<software_state::Profile> {
        let endpoints = Endpoints {
            api: Path::new("@qmp"),
            control: Path::new("@control"),
            backend: Path::new("@vsock-backend"),
            firmware: Path::new("@firmware"),
            tap: None,
        };
        let command = self.command(Path::new("@engine"), Path::new("@kernel"), Path::new("@rootfs"), &endpoints, network, disks)?;
        Ok(software_state::Profile {
            architecture: std::env::consts::ARCH.into(),
            arguments: command
                .get_args()
                .map(|arg| arg.to_str().map(str::to_owned).ok_or_else(|| "software profile contains a non-UTF8 argument".into()))
                .collect::<Result<_>>()?,
        })
    }

    pub fn boot(&self, rootfs: &Path, processes: Arc<Processes>, disks: Vec<volume::Writer>, routed: Option<Routed>) -> Result<Machine> {
        let inputs = software_state::Inputs::open(&self.qemu, &self.kernel, rootfs)?;
        let network = if routed.is_some() { Network::Routed } else { Network::Private };
        self.launch(inputs, processes, None, network, disks, routed)
    }

    pub fn boot_with_kernel(
        &self,
        rootfs: &Path,
        processes: Arc<Processes>,
        kernel: software_state::Input,
        disks: Vec<volume::Writer>,
        routed: Option<Routed>,
    ) -> Result<Machine> {
        let inputs = software_state::Inputs::with_kernel(&self.qemu, kernel, rootfs)?;
        let network = if routed.is_some() { Network::Routed } else { Network::Private };
        self.launch(inputs, processes, None, network, disks, routed)
    }

    /// Load state into a fresh engine, with CPUs paused and public admission closed.
    pub fn restore(
        &self,
        verified: software_state::Verified,
        processes: Arc<Processes>,
        disks: Vec<volume::Writer>,
        routed: Option<Routed>,
    ) -> Result<Machine> {
        if self.control != Control::Serial {
            bail!("software restore requires serial control");
        }
        let network = Network::from_profile(&verified.manifest.profile).ok_or("software restore has an unknown network profile")?;
        let disk_profile = Self::disk_profile(disks.iter().map(|disk| disk.id.as_str()));
        if self.profile_for(network, &disk_profile)? != verified.manifest.profile || verified.manifest.routed != routed.as_ref().map(|routed| routed.network) {
            bail!("software restore configuration changed after artifact validation");
        }
        verified.state.unchanged()?;
        let machine = self
            .launch(verified.inputs, processes, Some((&verified.state.file, &verified.manifest.engine_version)), network, disks, routed)
            .map_err(|error| format!("software incoming engine load failed: {error}"))?;
        verified.state.unchanged()?;
        Ok(machine)
    }

    fn launch(
        &self,
        inputs: software_state::Inputs,
        processes: Arc<Processes>,
        incoming: Option<(&File, &Value)>,
        network: Network,
        disks: Vec<volume::Writer>,
        routed: Option<Routed>,
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
        let engine = PathBuf::from(format!("/proc/self/fd/{}", inputs.engine.file.as_raw_fd()));
        let mut inherited = vec![inputs.engine.file.as_raw_fd(), inputs.kernel.file.as_raw_fd(), inputs.rootfs.file.as_raw_fd()];
        let mut machine = Machine {
            inputs: Some(inputs),
            disks,
            profile,
            network,
            routed,
            engine_version: Value::Null,
            capture: Mutex::default(),
            processes,
            sockets,
            logs,
            transport: self.control,
            control: Mutex::new(None),
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
            let tap = machine.routed.as_ref().map(|routed| routed.tap.as_raw_fd());
            inherited.extend(tap);
            let endpoints = Endpoints { api: &machine.sockets.api, control: &machine.sockets.vsock, backend: &machine.sockets.uffd, firmware: &firmware, tap };
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
            let clock = format!("{}.{:09}", now.as_secs(), now.subsec_nanos());
            let line = match &machine.routed {
                Some(routed) => {
                    let mut line = match routed.network.address.v6 {
                        Some(ip6) => format!("START6 {} {ip6} {clock}", routed.network.address.v4),
                        None => format!("START {} {clock}", routed.network.address.v4),
                    };
                    for dns in &routed.dns {
                        write!(line, " {dns}")?;
                    }
                    line
                }
                None => format!("START {} {clock} {}", network.ip().ok_or("missing software routed network")?, network.dns()),
            };
            let reply = machine.message(&line, deadline)?;
            if reply != b"ok" {
                bail!("software guest rejected network/clock setup: {}", String::from_utf8_lossy(&reply));
            }
            if let Some(routed) = &machine.routed {
                routed.publish()?;
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
    pub fn ip(&self) -> Option<std::net::Ipv4Addr> {
        self.routed.as_ref().map(|routed| routed.network.address.v4).or_else(|| self.network.ip())
    }

    pub fn restore_route(&self) -> Result<()> {
        if let Some(routed) = &self.routed {
            routed.publish()?;
        }
        Ok(())
    }

    pub fn release_routed_checkpoint(&self) {
        if let Some(routed) = &self.routed {
            routed.keep.store(false, Ordering::Relaxed);
        }
    }

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

    pub fn capture_pending(&self) -> bool {
        *self.capture.lock().unwrap() != Capture::None
    }

    pub fn checkpoint(
        &self,
        staging: software_state::Staging,
        destination: &Path,
        mut manifest: software_state::Manifest,
        previous: Option<&software_state::Consumed>,
        deadline: Instant,
    ) -> Result<software_state::Published> {
        if manifest.source_owner != crate::host::Ident::me() || manifest.source_engine != self.processes.engine_ident()? {
            bail!("software capture metadata does not identify this engine and owner");
        }
        manifest.routed = self.routed.as_ref().map(Routed::checkpoint).transpose()?;
        self.save(&staging.state, deadline)?;
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
        if let Some(routed) = &self.routed {
            routed.keep.store(true, Ordering::Relaxed);
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
        if status.success() && crate::fc::kernel_powered_off(&String::from_utf8_lossy(&console)) {
            return Ok(Some(0));
        }
        bail!("software distro engine exited without a completed guest power-off: {status}; {}", self.diagnostics())
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

    #[test]
    fn new_network_is_private_and_legacy_profiles_keep_the_original_command() {
        let config = Config {
            control: Control::Serial,
            kernel: PathBuf::new(),
            qemu: String::new(),
            vsock_backend: String::new(),
            mem_mib: 512,
            vcpus: 1,
            boot_timeout: Duration::from_secs(120),
        };
        let [private, legacy] = config.profiles().unwrap();
        assert_eq!(private, config.profile().unwrap());
        assert_eq!(Network::from_profile(&private), Some(Network::Private));
        assert_eq!(Network::from_profile(&legacy), Some(Network::Legacy));
        let kernel_args = |profile: &software_state::Profile| profile.arguments.windows(2).find(|args| args[0] == "-append").unwrap()[1].clone();
        assert!(kernel_args(&private).ends_with(" flexvm.gateway4=10.0.2.2"));
        assert!(!kernel_args(&legacy).contains("flexvm.gateway4="));
        let [routed] = <[_; 1]>::try_from(config.profiles_for_disk_ids(std::iter::empty(), true).unwrap()).unwrap();
        assert_eq!(Network::from_profile(&routed), Some(Network::Routed));
        assert!(!kernel_args(&routed).contains("flexvm.gateway4="));
        assert!(routed.arguments.iter().any(|arg| arg == "tap,id=net,fd=@tap,vhost=off"));
        assert!(routed.arguments.iter().any(|arg| arg.ends_with(",netdev=net,mac=06:00:ac:10:00:02")));
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
            vcpus: 1,
            boot_timeout: Duration::from_secs(60),
        };
        let source = Arc::new(Processes::default());
        let machine = config.boot(&rootfs, source.clone(), Vec::new(), None).unwrap();
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
            disks: Vec::new(),
            routed: None,
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
        let machine = config.restore(verified, target, Vec::new(), None).unwrap();
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
            routed: None,
            engine_version: Value::Null,
            capture: Mutex::default(),
            processes: Arc::new(Processes::default()),
            sockets,
            logs,
            transport: Control::Vsock,
            control: Mutex::new(None),
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
}
