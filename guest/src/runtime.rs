//! The app and execs share a mount/cgroup namespace rooted at the throttled /vm group.
//! PID 1 keeps the original mounts and stays outside that group, so it can lift memory.high.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::{Arc, OnceLock, RwLock};

use crate::{mem, os};

struct Namespaces {
    mount: File,
    cgroup: File,
    root: File,
}

static NAMESPACES: OnceLock<Namespaces> = OnceLock::new();

enum DistroState {
    Disabled,
    Waiting,
    Ready(Arc<DistroContext>),
}

static DISTRO: RwLock<DistroState> = RwLock::new(DistroState::Disabled);

/// One service generation's delegation and namespace view. A command retains
/// this whole generation until its fork has entered the group and namespaces.
pub(crate) struct DistroContext {
    namespaces: Namespaces,
    work: File,
    checks: File,
    _unit: File,
}

impl DistroContext {
    pub(crate) fn check_parent(&self) -> String {
        format!("/proc/self/fd/{}", self.checks.as_raw_fd())
    }
}

pub(crate) fn begin_distro() {
    *DISTRO.write().unwrap() = DistroState::Waiting;
}

pub(crate) fn distro_context() -> io::Result<Option<Arc<DistroContext>>> {
    match &*DISTRO.read().unwrap() {
        DistroState::Disabled => Ok(None),
        DistroState::Waiting => Err(io::Error::new(io::ErrorKind::WouldBlock, "distro runtime service is not ready")),
        DistroState::Ready(context) => Ok(Some(context.clone())),
    }
}

pub(crate) fn register_distro(unit: &str) -> io::Result<Arc<DistroContext>> {
    // The broker opens these from the initial cgroup namespace. A descriptor
    // opened by the service itself would retain that narrower delegation view.
    let unit = File::open(unit)?;
    if !unit.metadata()?.is_dir() {
        return Err(io::Error::other("runtime delegation is not a directory"));
    }
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    os(unsafe { libc::fstatfs(unit.as_raw_fd(), &mut filesystem) })?;
    if filesystem.f_type as u64 != 0x6367_7270 {
        return Err(io::Error::other("runtime delegation is not on cgroup v2"));
    }
    // Pin the unit directory before opening its children: a concurrent restart
    // must not combine old work with a newly recreated unit's check directory.
    let root = format!("/proc/self/fd/{}", unit.as_raw_fd());
    let context = Arc::new(DistroContext {
        namespaces: Namespaces { mount: File::open("/proc/1/ns/mnt")?, cgroup: File::open("/proc/1/ns/cgroup")?, root: File::open("/proc/1/root")? },
        work: File::options().write(true).open(format!("{root}/work/cgroup.procs"))?,
        checks: File::open(format!("{root}/check"))?,
        _unit: unit,
    });
    *DISTRO.write().unwrap() = DistroState::Ready(context.clone());
    Ok(context)
}

pub(crate) fn unregister_distro(context: &Arc<DistroContext>) {
    let mut state = DISTRO.write().unwrap();
    if matches!(&*state, DistroState::Ready(current) if Arc::ptr_eq(current, context)) {
        *state = DistroState::Waiting;
    }
}

/// Called before PID 1 starts any threads. The helper enters /vm to create its cgroup namespace;
/// holding its namespace fds keeps the view alive after it exits, without moving PID 1 into /vm.
pub fn prepare() -> io::Result<()> {
    let (mut parent, mut child) = UnixStream::pair()?;
    let pid = os(unsafe { libc::fork() })?;
    if pid == 0 {
        drop(parent);
        let errno = prepare_child().err().map_or(0, |e| e.raw_os_error().unwrap_or(libc::EIO));
        let _ = child.write_all(&errno.to_ne_bytes());
        // Keep /proc/PID/ns available until the parent has opened both namespace fds.
        let _ = child.read(&mut [0]);
        unsafe { libc::_exit(if errno == 0 { 0 } else { 1 }) };
    }
    drop(child);
    let result = (|| {
        let mut errno = [0; 4];
        parent.read_exact(&mut errno)?;
        let errno = i32::from_ne_bytes(errno);
        if errno != 0 {
            return Err(io::Error::from_raw_os_error(errno));
        }
        Ok(Namespaces {
            mount: File::open(format!("/proc/{pid}/ns/mnt"))?,
            cgroup: File::open(format!("/proc/{pid}/ns/cgroup"))?,
            root: File::open(format!("/proc/{pid}/root"))?,
        })
    })();
    drop(parent);
    while unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) } < 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    NAMESPACES.set(result?).map_err(|_| io::Error::other("runtime namespaces already prepared"))
}

fn prepare_child() -> io::Result<()> {
    std::fs::write(format!("{}/cgroup.procs", mem::CGROUP), "0")?;
    os(unsafe { libc::unshare(libc::CLONE_NEWCGROUP | libc::CLONE_NEWNS) })?;
    // Remount cgroup2 in the new cgroup namespace: inheriting the old mount would still expose
    // kernel threads and PID 1, which DinD's cgroup setup cannot move into its /init group.
    crate::mount("", "/", "", libc::MS_REC | libc::MS_PRIVATE, "")?;
    os(unsafe { libc::umount2(c"/sys/fs/cgroup".as_ptr(), libc::MNT_DETACH) })?;
    crate::mount("cgroup2", mem::CGROUP_ROOT, "cgroup2", 0, "")
}

/// After entering the child's work/check cgroup, before dropping its credentials. Execs join the
/// same mount namespace as the app, so mounts made by the app are visible to later commands.
pub fn enter(cmd: &mut Command) -> io::Result<()> {
    if let Some(context) = distro_context()? {
        let work = context.work.as_raw_fd();
        let retained = context.clone();
        unsafe {
            cmd.pre_exec(move || {
                let _keep_alive = &retained;
                if libc::write(work, b"0".as_ptr().cast(), 1) != 1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        return enter_in(cmd, &context.namespaces);
    }
    let Some(ns) = NAMESPACES.get() else { return Ok(()) };
    enter_in(cmd, ns)
}

/// Checks have already entered their private child group. Keep the matching
/// namespace generation, rather than replacing their group with ordinary work.
pub(crate) fn enter_check(cmd: &mut Command, context: &Arc<DistroContext>) -> io::Result<()> {
    let retained = context.clone();
    unsafe {
        cmd.pre_exec(move || {
            let _keep_alive = &retained;
            Ok(())
        });
    }
    enter_in(cmd, &context.namespaces)
}

fn enter_in(cmd: &mut Command, ns: &Namespaces) -> io::Result<()> {
    let (mount, cgroup) = (ns.mount.as_raw_fd(), ns.cgroup.as_raw_fd());
    // Command applies its cwd before pre_exec, but setns(CLONE_NEWNS) resets
    // pwd/root to the new namespace's root. Resolve the requested path again
    // after entering, so it also sees mounts made by the app in that namespace.
    let cwd = cmd.get_current_dir().map(std::path::absolute).transpose()?;
    let cwd = cwd.map(|p| CString::new(p.as_os_str().as_bytes())).transpose()?;
    if cwd.is_some() {
        // std performs its chdir before pre_exec. The requested directory may
        // exist only in the target mount namespace, so defer that lookup too.
        cmd.current_dir("/");
    }
    unsafe {
        cmd.pre_exec(move || {
            os(libc::setns(cgroup, libc::CLONE_NEWCGROUP))?;
            os(libc::setns(mount, libc::CLONE_NEWNS))?;
            if let Some(cwd) = &cwd {
                os(libc::chdir(cwd.as_ptr()))?;
            }
            Ok(())
        });
    }
    Ok(())
}

fn open_root_file(root: &File, path: &str, flags: u64) -> io::Result<File> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let path = CString::new(path)?;
    // Absolute symlinks must remain inside the target namespace's root, rather
    // than jumping back into the broker's earlier mount view.
    let how = OpenHow { flags: flags | libc::O_CLOEXEC as u64, mode: 0, resolve: 0x10 }; // RESOLVE_IN_ROOT
    let fd = os(unsafe { libc::syscall(libc::SYS_openat2, root.as_raw_fd(), path.as_ptr(), &how, std::mem::size_of::<OpenHow>()) })?;
    Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(fd as i32) })
}

pub(crate) fn root_file(path: &str, flags: u64) -> io::Result<File> {
    if let Some(context) = distro_context()? {
        return open_root_file(&context.namespaces.root, path, flags);
    }
    if let Some(ns) = NAMESPACES.get() {
        return open_root_file(&ns.root, path, flags);
    }
    File::options().read(true).custom_flags(flags as i32).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root to enter mount/cgroup namespaces"]
    fn requested_workdir_survives_real_mount_namespace_entry() {
        let ns =
            Namespaces { mount: File::open("/proc/self/ns/mnt").unwrap(), cgroup: File::open("/proc/self/ns/cgroup").unwrap(), root: File::open("/").unwrap() };
        let cwd = std::env::current_dir().unwrap();
        assert_ne!(cwd, std::path::Path::new("/"));
        for requested in [cwd.as_path(), std::path::Path::new(".")] {
            let expected = std::path::absolute(requested).unwrap();
            let mut cmd = Command::new("/bin/pwd");
            cmd.current_dir(requested);
            enter_in(&mut cmd, &ns).unwrap();
            let output = cmd.output().unwrap();
            assert!(output.status.success(), "{output:?}");
            assert_eq!(output.stdout, [expected.as_os_str().as_bytes(), b"\n"].concat());
        }
    }
}
