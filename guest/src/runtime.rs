//! The app and execs share a mount/cgroup namespace rooted at the throttled /vm group.
//! PID 1 keeps the original mounts and stays outside that group, so it can lift memory.high.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::OnceLock;

use crate::{mem, os};

struct Namespaces {
    mount: File,
    cgroup: File,
}

static NAMESPACES: OnceLock<Namespaces> = OnceLock::new();

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
        Ok(Namespaces { mount: File::open(format!("/proc/{pid}/ns/mnt"))?, cgroup: File::open(format!("/proc/{pid}/ns/cgroup"))? })
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
pub fn enter(cmd: &mut Command) {
    let Some(ns) = NAMESPACES.get() else { return };
    let (mount, cgroup) = (ns.mount.as_raw_fd(), ns.cgroup.as_raw_fd());
    unsafe {
        cmd.pre_exec(move || {
            os(libc::setns(cgroup, libc::CLONE_NEWCGROUP))?;
            os(libc::setns(mount, libc::CLONE_NEWNS))?;
            Ok(())
        });
    }
}
