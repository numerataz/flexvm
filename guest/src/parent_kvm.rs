//! Load the parent KVM frontend from the dedicated read-only block attachment.

use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"FLEXKVM1";
const MAX_MODULE_BYTES: u32 = 4 << 20;
const SERIAL: &str = "flexvm-pvkvm";

pub fn load_if_requested(cmdline: &str) -> io::Result<()> {
    let mut mode = cmdline.split_whitespace().filter_map(|arg| arg.strip_prefix("flexvm.kvm="));
    match (mode.next(), mode.next()) {
        (None, None) => return Ok(()),
        (Some("parent"), None) if cfg!(target_arch = "x86_64") => {}
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid guest KVM provider boot argument")),
    }
    load()
}

fn module_device() -> io::Result<PathBuf> {
    let mut image = None;
    for entry in fs::read_dir("/sys/class/block")? {
        let entry = entry?;
        let path = entry.path();
        let serial = match fs::read_to_string(path.join("serial")) {
            Ok(serial) => serial,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if serial.trim() == SERIAL {
            if fs::read_to_string(path.join("ro"))?.trim() != "1" || image.is_some() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "ambiguous or writable parent KVM module attachment"));
            }
            image = Some(Path::new("/dev").join(entry.file_name()));
        }
    }
    let image = image.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "parent KVM module attachment is missing"))?;
    if !fs::symlink_metadata(&image)?.file_type().is_block_device() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "parent KVM module attachment must be a block device"));
    }
    Ok(image)
}

fn copy_module(mut source: impl Read, mut dest: impl io::Write) -> io::Result<()> {
    let mut header = [0; 12];
    source.read_exact(&mut header)?;
    let size = u32::from_le_bytes(header[8..].try_into().expect("fixed module header"));
    if &header[..8] != MAGIC || !(1..=MAX_MODULE_BYTES).contains(&size) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid parent KVM module header"));
    }
    let size = u64::from(size);
    if io::copy(&mut source.take(size), &mut dest)? != size {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated parent KVM module"));
    }
    Ok(())
}

fn load() -> io::Result<()> {
    match fs::symlink_metadata("/dev/kvm") {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
        Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "/dev/kvm already has a guest provider")),
    }
    let image = File::open(module_device()?)?;
    let fd = crate::os(unsafe { libc::memfd_create(c"flexvm-pvkvm".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) })?;
    let module = unsafe { File::from_raw_fd(fd) };
    copy_module(image, &module)?;
    let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    crate::os(unsafe { libc::fcntl(module.as_raw_fd(), libc::F_ADD_SEALS, seals) })?;
    let readonly = File::open(format!("/proc/self/fd/{fd}"))?;
    drop(module);
    crate::os(unsafe { libc::syscall(libc::SYS_finit_module, readonly.as_raw_fd(), c"".as_ptr(), 0) })?;
    let device = File::open("/dev/kvm")?;
    if crate::os(unsafe { libc::ioctl(device.as_raw_fd(), 0xae00, 0) })? != 12 {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "unexpected parent KVM API version"));
    }
    crate::log("parent KVM provider ready");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_module_payload_before_loading() {
        let mut image = [MAGIC.as_slice(), &3u32.to_le_bytes(), &[1, 2, 3, 0, 0]].concat();
        let mut copied = Vec::new();
        copy_module(image.as_slice(), &mut copied).unwrap();
        assert_eq!(copied, [1, 2, 3]);
        assert_eq!(copy_module(&image[..14], io::sink()).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        image[8..12].copy_from_slice(&(MAX_MODULE_BYTES + 1).to_le_bytes());
        assert_eq!(copy_module(image.as_slice(), io::sink()).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
