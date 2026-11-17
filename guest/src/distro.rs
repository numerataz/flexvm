//! Distro PID 1 bootstrap. The broker keeps the existing management transport;
//! the init-managed runtime service supplies only its delegated workload tree.
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::app::BootProfile;
use crate::{mem, os, runtime};

const DIRECTORY: &str = "/run/flexvm";
const SOCKET: &str = "/run/flexvm/broker.sock";
const ENVIRONMENT: &str = "/run/flexvm/init.env";
struct Broker {
    gate: Mutex<Option<UnixStream>>,
}
static BROKER: OnceLock<Broker> = OnceLock::new();
static INIT_FAILURE: Mutex<Option<String>> = Mutex::new(None);

pub(crate) fn is_broker() -> bool {
    BROKER.get().is_some()
}

pub(crate) fn init_path(profile: BootProfile) -> io::Result<&'static str> {
    match profile {
        BootProfile::Systemd => Ok("/sbin/init"),
        BootProfile::Openrc => Ok("/sbin/openrc-init"),
        BootProfile::App => Err(io::Error::other("app mode has no distro init")),
    }
}

/// Called in single-threaded PID 1 after mounting its root and network devices.
pub(crate) fn boot(profile: BootProfile) -> io::Result<()> {
    mem::prepare_distro()?;
    fs::create_dir_all(DIRECTORY)?;
    fs::set_permissions(DIRECTORY, fs::Permissions::from_mode(0o700))?;
    let (mut parent, child) = UnixStream::pair()?;
    let descriptor = child.as_raw_fd();
    let mut command = Command::new("/proc/self/exe");
    // systemd's Root Storage Daemon convention preserves this process through
    // shutdown; it must keep the memory watcher and management state alive.
    command.arg0("@flexvm-broker").arg("--distro-broker").arg(descriptor.to_string());
    unsafe {
        command.pre_exec(move || {
            os(libc::fcntl(descriptor, libc::F_SETFD, 0))?;
            Ok(())
        });
    }
    let _broker = command.spawn()?;
    drop(child);
    parent.set_read_timeout(Some(Duration::from_secs(15)))?;
    receive(&mut parent, b'B')?;
    // /vm is still a leaf here. Enabling its controllers before this move
    // would reject PID 1 with EBUSY because of the no-internal-processes rule.
    fs::write(format!("{}/cgroup.procs", mem::CGROUP), "0")?;
    os(unsafe { libc::unshare(libc::CLONE_NEWCGROUP | libc::CLONE_NEWNS) })?;
    crate::mount("", "/", "", libc::MS_REC | libc::MS_PRIVATE, "")?;
    os(unsafe { libc::umount2(c"/sys/fs/cgroup".as_ptr(), libc::MNT_DETACH) })?;
    crate::mount("cgroup2", mem::CGROUP_ROOT, "cgroup2", libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV, "nsdelegate,memory_recursiveprot")?;
    // systemd creates init.scope and enables its own subtree controllers.
    // The bootstrap owns only the outer pressure boundary and broker tree.
    parent.write_all(b"R")?;
    // Templates and standby VMs remain here. No real init/service identity has
    // started until the owner supplies per-VM settings and releases this gate.
    parent.set_read_timeout(None)?;
    receive(&mut parent, b'G')?;
    // CLOEXEC closes this gate on successful exec. A failed exec reports its
    // cause to the still-responsive broker instead of waiting out readiness.
    let result = (|| {
        let environment = crate::app::distro_environment(&fs::read_to_string(ENVIRONMENT)?)?;
        Err(Command::new(init_path(profile)?).current_dir("/").env_clear().envs(environment).exec())
    })();
    if let Err(error) = &result {
        let message = format!("distro init exec failed: {error}");
        let _ = parent.write_all(&message.as_bytes()[..message.len().min(1024)]);
    }
    result
}

fn receive(stream: &mut UnixStream, expected: u8) -> io::Result<()> {
    let mut value = [0];
    stream.read_exact(&mut value)?;
    if value[0] != expected {
        return Err(io::Error::other("invalid distro bootstrap handshake"));
    }
    Ok(())
}

/// Initialize the broker, then return to the normal guest management server.
pub(crate) fn broker(descriptor: i32) -> io::Result<()> {
    if descriptor < 3 || crate::app::boot_profile()? == BootProfile::App {
        return Err(io::Error::other("invalid distro broker role"));
    }
    let mut gate = unsafe { UnixStream::from_raw_fd(descriptor) };
    os(unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    fs::write("/sys/fs/cgroup/flexvm/broker/cgroup.procs", "0")?;
    // PID 1 was immune to the OOM killer in app mode; this broker is no longer
    // PID 1, but still needs to lift the mark when workloads exhaust their RAM.
    fs::write("/proc/self/oom_score_adj", "-1000")?;
    gate.write_all(b"B")?;
    receive(&mut gate, b'R')?;
    runtime::begin_distro();
    BROKER.set(Broker { gate: Mutex::new(Some(gate)) }).map_err(|_| io::Error::other("broker initialized twice"))?;
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600))?;
    std::thread::Builder::new().name("distro-runtime".into()).spawn(move || registrations(listener))?;
    mem::start_distro()
}

pub(crate) fn atomic_file(path: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
    let temporary = format!("{path}.flexvm-new");
    let _ = fs::remove_file(&temporary);
    let mut file = File::options().write(true).create_new(true).open(&temporary)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(bytes)?;
    let renamed = fs::rename(&temporary, path);
    if renamed.as_ref().is_err_and(|error| error.raw_os_error() == Some(libc::EBUSY)) {
        let result = crate::rewrite_bound_file(std::path::Path::new(path), bytes);
        let _ = fs::remove_file(&temporary);
        return result;
    }
    renamed
}

/// Idempotent across an APP retry: a released gate never assigns a new identity.
pub(crate) fn release(environment: &str) -> io::Result<bool> {
    let broker = BROKER.get().ok_or_else(|| io::Error::other("not a distro broker"))?;
    let mut held = broker.gate.lock().unwrap();
    let Some(gate) = held.as_mut() else { return Ok(false) };
    atomic_file(ENVIRONMENT, environment.as_bytes(), 0o600)?;
    // The normal owner already waits for VMGenID reseeding before START/APP.
    // Software boots are fresh kernels; resumes never pass this cold gate.
    let mut entropy = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut entropy)?;
    let identity = entropy.iter().map(|value| format!("{value:02x}")).collect::<String>() + "\n";
    atomic_file("/etc/machine-id", identity.as_bytes(), 0o444)?;
    let mut hostname = [0u8; 256];
    os(unsafe { libc::gethostname(hostname.as_mut_ptr().cast(), hostname.len()) })?;
    let length = hostname.iter().position(|byte| *byte == 0).ok_or_else(|| io::Error::other("unterminated guest hostname"))?;
    let mut name = hostname[..length].to_vec();
    name.push(b'\n');
    atomic_file("/etc/hostname", &name, 0o644)?;
    if fs::metadata("/var/lib/dbus").is_ok_and(|meta| meta.is_dir()) {
        atomic_file("/var/lib/dbus/machine-id", identity.as_bytes(), 0o444)?;
    }
    gate.write_all(b"G")?;
    let stream = held.take().unwrap();
    std::thread::Builder::new().name("distro-init-result".into()).spawn(move || {
        let mut message = String::new();
        match stream.take(1024).read_to_string(&mut message) {
            Ok(_) if message.is_empty() => (), // successful exec closed the CLOEXEC gate
            result => {
                let failure = result.err().map_or(message, |error| format!("distro init result: {error}"));
                *INIT_FAILURE.lock().unwrap() = Some(failure);
            }
        }
    })?;
    Ok(true)
}

pub(crate) fn status() -> String {
    if let Some(error) = &*INIT_FAILURE.lock().unwrap() {
        return format!("failed {error}");
    }
    match BROKER.get() {
        None => "idle",
        Some(broker) if broker.gate.lock().unwrap().is_some() => "idle",
        Some(_) if runtime::distro_context().is_ok_and(|context| context.is_some()) => "running 1",
        Some(_) => "starting 1",
    }
    .into()
}

fn peer_unit(stream: &UnixStream) -> io::Result<String> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    os(unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut credentials as *mut libc::ucred).cast(), &mut size) })?;
    if credentials.uid != 0 || credentials.pid <= 1 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "runtime registration requires a root service"));
    }
    let current = fs::read_to_string(format!("/proc/{}/cgroup", credentials.pid))?;
    let group = current.lines().find_map(|line| line.strip_prefix("0::")).ok_or_else(|| io::Error::other("service has no unified cgroup"))?;
    let unit = group
        .strip_suffix("/sup")
        .filter(|unit| unit.starts_with("/vm/") && !unit.split('/').any(|part| matches!(part, "." | "..")))
        .ok_or_else(|| io::Error::other("runtime service is outside its delegated supervisor group"))?;
    Ok(format!("/sys/fs/cgroup{unit}"))
}

fn registrations(listener: UnixListener) {
    // One provider connection at a time: no unbounded privileged worker threads.
    for connection in listener.incoming() {
        let result = connection.and_then(|mut stream| {
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut request = String::new();
            BufReader::new((&mut stream).take(32)).read_line(&mut request)?;
            if request != "REGISTER\n" {
                return Err(io::Error::other("invalid runtime registration"));
            }
            let unit = peer_unit(&stream)?;
            let context = runtime::register_distro(&unit)?;
            let result = (|| {
                stream.write_all(b"ok\n")?;
                stream.set_read_timeout(None)?;
                let mut byte = [0];
                match stream.read(&mut byte) {
                    Ok(0) => Ok(()),
                    Ok(_) => Err(io::Error::other("unexpected runtime provider data")),
                    Err(error) => Err(error),
                }
            })();
            runtime::unregister_distro(&context);
            result
        });
        if let Err(error) = result {
            crate::log(&format!("distro runtime registration: {error}"));
        }
    }
}

/// systemd owns the unit root; this process owns only its delegated children.
pub(crate) fn provider() -> io::Result<()> {
    if crate::app::boot_profile()? == BootProfile::App {
        return Err(io::Error::other("runtime provider requires distro boot"));
    }
    let current = fs::read_to_string("/proc/self/cgroup")?;
    let group = current.lines().find_map(|line| line.strip_prefix("0::")).ok_or_else(|| io::Error::other("no unified service cgroup"))?;
    if group == "/" || group.split('/').any(|part| matches!(part, "." | "..")) {
        return Err(io::Error::other("runtime provider requires a delegated service cgroup"));
    }
    let unit = format!("/sys/fs/cgroup{group}");
    for leaf in ["sup", "work", "check"] {
        fs::create_dir_all(format!("{unit}/{leaf}"))?;
    }
    fs::write(format!("{unit}/sup/cgroup.procs"), "0")?;
    mem::enable_controllers(&unit)?;
    mem::enable_controllers(&format!("{unit}/check"))?;
    let mut stream = UnixStream::connect(SOCKET)?;
    stream.write_all(b"REGISTER\n")?;
    let mut reply = [0; 3];
    stream.read_exact(&mut reply)?;
    if &reply != b"ok\n" {
        return Err(io::Error::other("runtime broker refused delegation"));
    }
    notify_ready()?;
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(0) => Err(io::Error::other("distro broker disconnected")),
        Ok(_) => Err(io::Error::other("unexpected broker data")),
        Err(error) => Err(error),
    }
}

fn notify_ready() -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return Ok(()) };
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() {
        return Err(io::Error::other("invalid systemd notification socket"));
    }
    address.sun_family = libc::AF_UNIX as _;
    for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *source as _;
    }
    let extra = if bytes[0] == b'@' {
        address.sun_path[0] = 0;
        0
    } else {
        1
    };
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + extra;
    let socket = os(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) })?;
    let socket = unsafe { File::from_raw_fd(socket) };
    os(unsafe { libc::sendto(socket.as_raw_fd(), b"READY=1\n".as_ptr().cast(), 8, 0, (&address as *const libc::sockaddr_un).cast(), length as _) })?;
    Ok(())
}
