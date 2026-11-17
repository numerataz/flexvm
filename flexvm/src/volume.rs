//! Private sparse raw volumes. VM attachment and checkpoint generations are separate work.
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::bail;
use crate::util::{self, Result};

const MAX_BYTES: u64 = 8 << 40;
const MEMBERS: [&str; 2] = ["disk.raw", "metadata.json"];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema_version: u32,
    id: String,
    name: String,
    capacity_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct Info {
    #[serde(flatten)]
    metadata: Metadata,
    allocated_bytes: u64,
}

pub struct Catalog {
    directory: File,
}

pub(crate) struct Writer {
    pub id: String,
    pub size: u64,
    pub file: File,
}

pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !valid_id(name)
}

fn capacity(bytes: u64) -> Result<()> {
    if bytes == 0 || bytes > MAX_BYTES || bytes % 512 != 0 {
        bail!("volume size must be a multiple of 512 bytes, from 512 bytes to 8 TiB");
    }
    Ok(())
}

fn copy_sparse(source: &File, target: &File, size: u64) -> Result<()> {
    let mut buffer = vec![0; 1 << 20];
    let mut offset = 0;
    let mut seek_holes = true;
    while offset < size {
        let end = if seek_holes {
            let data = unsafe { libc::lseek(source.as_raw_fd(), offset as libc::off_t, libc::SEEK_DATA) };
            if data < 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::ENXIO) => break,
                    Some(libc::EINVAL | libc::EOPNOTSUPP | libc::ENOSYS) => {
                        seek_holes = false;
                        continue;
                    }
                    _ => return Err(error.into()),
                }
            }
            let hole = unsafe { libc::lseek(source.as_raw_fd(), data, libc::SEEK_HOLE) };
            if hole < 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EINVAL | libc::EOPNOTSUPP | libc::ENOSYS) => {
                        seek_holes = false;
                        continue;
                    }
                    _ => return Err(error.into()),
                }
            }
            if data < offset as libc::off_t || data as u64 >= size || hole <= data {
                bail!("invalid source volume extent");
            }
            offset = data as u64;
            (hole as u64).min(size)
        } else {
            size
        };
        while offset < end {
            let bytes = (end - offset).min(buffer.len() as u64) as usize;
            source.read_exact_at(&mut buffer[..bytes], offset)?;
            // Also preserve sparsity when a filesystem reports holes as data.
            if buffer[..bytes].iter().any(|byte| *byte != 0) {
                target.write_all_at(&buffer[..bytes], offset)?;
            }
            offset += bytes as u64;
        }
    }
    Ok(())
}

pub(crate) fn copy_raw(source: &File, target: &File, size: u64) -> Result<()> {
    loop {
        if unsafe { libc::ioctl(target.as_raw_fd(), libc::FICLONE, source.as_raw_fd()) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EBADF | libc::EINVAL | libc::ENOTTY | libc::EOPNOTSUPP | libc::EXDEV | libc::ENOSYS | libc::EPERM) => break,
            _ => return Err(error.into()),
        }
    }
    // A failed optional clone must not leave data in holes of the fallback copy.
    target.set_len(0)?;
    target.set_len(size)?;
    copy_sparse(source, target, size)
}

fn make_directory(parent: &File, name: &std::ffi::CStr) -> Result<()> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    Ok(())
}

fn directory(parent: &File, name: &str) -> Result<File> {
    let dir: File = util::open_dir_at(parent.as_raw_fd(), &util::cname(name))?.into();
    let stat = dir.metadata()?;
    if stat.uid() != unsafe { libc::geteuid() } || stat.mode() & 0o077 != 0 {
        bail!("volume directory is not private to its owner");
    }
    Ok(dir)
}

fn member(dir: &File, name: &str, flags: i32) -> Result<File> {
    let file: File = util::openat(dir.as_raw_fd(), &util::cname(name), flags | libc::O_NOFOLLOW | libc::O_NONBLOCK)?.into();
    let stat = file.metadata()?;
    if !stat.is_file() || stat.uid() != unsafe { libc::geteuid() } || stat.mode() & 0o077 != 0 || stat.nlink() != 1 {
        bail!("volume member is not a private, singly linked regular file");
    }
    Ok(file)
}

fn entries(dir: &File) -> Result<Vec<String>> {
    fs::read_dir(crate::host::fd_path(dir.as_raw_fd()))?
        .map(|entry| entry?.file_name().into_string().map_err(|_| "invalid volume catalog entry".into()))
        .collect()
}

fn rename(parent: &File, from: &str, to: &str) -> Result<()> {
    let (from, to) = (util::cname(from), util::cname(to));
    util::check(unsafe { libc::renameat2(parent.as_raw_fd(), from.as_ptr(), parent.as_raw_fd(), to.as_ptr(), libc::RENAME_NOREPLACE) })?;
    parent.sync_all()?;
    Ok(())
}

impl Catalog {
    pub fn open(state: &Path) -> Result<Self> {
        // Sync both new directory entries before publishing any volume below them.
        // The selected state's parent must already exist.
        let parent = state.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let parent = File::options().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(parent)?;
        let name = util::cpath(Path::new(state.file_name().ok_or("volume state needs a directory name")?))?;
        make_directory(&parent, &name)?;
        let state: File = util::open_dir_at(parent.as_raw_fd(), &name)?.into();
        let stat = state.metadata()?;
        if stat.uid() != unsafe { libc::geteuid() } || stat.mode() & 0o022 != 0 {
            bail!("volume state directory is writable by another user or owned by someone else");
        }
        parent.sync_all()?;
        make_directory(&state, c"volumes")?;
        let directory = directory(&state, "volumes")?;
        state.sync_all()?;
        Ok(Self { directory })
    }

    // Locks the stable catalog directory inode. It is never unlinked by catalog operations.
    fn lock(&self, how: i32) -> Result<crate::host::Flock> {
        let lock: File = util::open_dir_at(self.directory.as_raw_fd(), c".")?.into();
        crate::host::flock(&lock, how | libc::LOCK_NB).map_err(|error| format!("volume catalog is busy: {error}"))?;
        Ok(crate::host::Flock(lock))
    }

    fn read(&self, id: &str) -> Result<(Info, File, File)> {
        if !valid_id(id) {
            bail!("invalid volume identifier");
        }
        let dir = directory(&self.directory, id)?;
        let mut bytes = Vec::new();
        member(&dir, "metadata.json", libc::O_RDONLY)?.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            bail!("volume metadata is too large");
        }
        let metadata: Metadata = serde_json::from_slice(&bytes)?;
        if metadata.schema_version != 1 || metadata.id != id || !valid_name(&metadata.name) {
            bail!("unsupported or inconsistent volume metadata");
        }
        capacity(metadata.capacity_bytes)?;
        let disk = member(&dir, "disk.raw", libc::O_RDWR)?;
        let stat = disk.metadata()?;
        if stat.len() != metadata.capacity_bytes {
            bail!("volume backing size differs from its declared capacity");
        }
        Ok((Info { metadata, allocated_bytes: stat.blocks().saturating_mul(512) }, dir, disk))
    }

    fn volumes(&self) -> Result<Vec<Info>> {
        let mut volumes = Vec::new();
        for id in entries(&self.directory)? {
            if valid_id(&id) {
                volumes.push(self.read(&id)?.0);
            } else if ![".creating-v1-", ".deleting-v1-"].iter().any(|prefix| id.strip_prefix(prefix).is_some_and(valid_id)) {
                bail!("unrecognized volume catalog entry {id:?}");
            }
        }
        volumes.sort_by(|a, b| a.metadata.name.cmp(&b.metadata.name));
        Ok(volumes)
    }

    fn find(&self, name: &str) -> Result<Info> {
        let mut matches = self.volumes()?.into_iter().filter(|v| v.metadata.id == name || v.metadata.name == name);
        let found = matches.next().ok_or_else(|| format!("volume {name:?} does not exist"))?;
        if matches.next().is_some() {
            bail!("ambiguous volume name");
        }
        Ok(found)
    }

    /// Remove only our two known members, relative to validated directory descriptors.
    /// A live writer's inherited disk flock must remain held until the engine exits.
    fn cleanup(&self, name: &str) -> Result<()> {
        let dir = directory(&self.directory, name)?;
        let names = entries(&dir)?;
        if names.iter().any(|n| !MEMBERS.contains(&n.as_str())) {
            bail!("unrecognized member in retired volume");
        }
        let mut held = Vec::new();
        for name in &names {
            let file = member(&dir, name, libc::O_RDWR)?;
            crate::host::flock(&file, libc::LOCK_EX | libc::LOCK_NB).map_err(|error| format!("retired volume is still in use: {error}"))?;
            held.push(file);
        }
        for name in names {
            util::check(unsafe { libc::unlinkat(dir.as_raw_fd(), util::cname(&name).as_ptr(), 0) })?;
        }
        dir.sync_all()?;
        util::check(unsafe { libc::unlinkat(self.directory.as_raw_fd(), util::cname(name).as_ptr(), libc::AT_REMOVEDIR) })?;
        self.directory.sync_all()?;
        Ok(())
    }

    fn recover(&self) -> Result<()> {
        for name in entries(&self.directory)? {
            if [".creating-v1-", ".deleting-v1-"].iter().any(|prefix| name.strip_prefix(prefix).is_some_and(valid_id)) {
                self.cleanup(&name)?;
            }
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<Info>> {
        let _catalog = self.lock(libc::LOCK_SH)?;
        self.volumes()
    }

    pub fn inspect(&self, name: &str) -> Result<Info> {
        let _catalog = self.lock(libc::LOCK_SH)?;
        self.find(name)
    }

    pub fn create(&self, name: &str, size: u64) -> Result<Info> {
        let _catalog = self.lock(libc::LOCK_EX)?;
        self.create_locked(name, size, |_| Ok(()))
    }

    fn locked_writer(&self, source: &str) -> Result<(Info, File)> {
        let info = self.find(source)?;
        let (_, _, disk) = self.read(&info.metadata.id)?;
        crate::host::flock(&disk, libc::LOCK_EX | libc::LOCK_NB).map_err(|error| format!("volume {source:?} is still in use: {error}"))?;
        Ok((info, disk))
    }

    /// Opening and taking the per-volume lease must precede releasing the
    /// catalog lock. Removal and cloning take the same backing-file lease.
    pub(crate) fn writer(&self, volume: &str) -> Result<Writer> {
        let _catalog = self.lock(libc::LOCK_SH)?;
        let (info, file) = self.locked_writer(volume)?;
        Ok(Writer { id: info.metadata.id, size: info.metadata.capacity_bytes, file })
    }

    pub fn clone_volume(&self, source: &str, name: &str) -> Result<Info> {
        let _catalog = self.lock(libc::LOCK_EX)?;
        let (info, disk) = self.locked_writer(source)?;
        self.create_locked(name, info.metadata.capacity_bytes, |target| {
            copy_raw(&disk, target, info.metadata.capacity_bytes)?;
            if disk.metadata()?.len() != info.metadata.capacity_bytes {
                bail!("source volume capacity changed during clone");
            }
            Ok(())
        })
    }

    // The caller holds the catalog mutation lock through population and publication.
    fn create_locked(&self, name: &str, size: u64, populate: impl FnOnce(&File) -> Result<()>) -> Result<Info> {
        if !valid_name(name) {
            bail!("volume names must be 1–63 ASCII letters/digits/._-, start with a letter or digit, and not be a 32-digit hexadecimal identifier");
        }
        capacity(size)?;
        self.recover()?;
        if self.volumes()?.iter().any(|v| v.metadata.name == name) {
            bail!("volume {name:?} already exists");
        }
        let id = util::random_hex(16)?;
        let staging = format!(".creating-v1-{id}");
        util::check(unsafe { libc::mkdirat(self.directory.as_raw_fd(), util::cname(&staging).as_ptr(), 0o700) })?;
        let metadata = Metadata { schema_version: 1, id: id.clone(), name: name.into(), capacity_bytes: size };
        let dir = directory(&self.directory, &staging)?;
        let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL;
        let disk = member(&dir, "disk.raw", flags)?;
        disk.set_len(size)?;
        populate(&disk)?;
        if disk.metadata()?.len() != size {
            bail!("new volume capacity differs from its declared capacity");
        }
        disk.sync_all()?;
        let mut record = member(&dir, "metadata.json", flags)?;
        record.write_all(&serde_json::to_vec(&metadata)?)?;
        record.sync_all()?;
        dir.sync_all()?;
        rename(&self.directory, &staging, &id)?;
        Ok(self.read(&id)?.0)
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        let _catalog = self.lock(libc::LOCK_EX)?;
        self.recover()?;
        let volume = self.find(name)?;
        let id = volume.metadata.id;
        let (_, dir, disk) = self.read(&id)?;
        if entries(&dir)?.iter().any(|n| !MEMBERS.contains(&n.as_str())) {
            bail!("unrecognized volume member; removal refused");
        }
        crate::host::flock(&disk, libc::LOCK_EX | libc::LOCK_NB).map_err(|error| format!("volume is still in use: {error}"))?;
        let tombstone = format!(".deleting-v1-{id}");
        rename(&self.directory, &id, &tombstone)?;
        // cleanup obtains a fresh flock, so release only this local removal hold.
        drop(disk);
        self.cleanup(&tombstone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    #[test]
    fn retained_sparse_volume_has_stable_identity_and_data() {
        let state = crate::test_util::TempDir::new("volume");
        let catalog = Catalog::open(&state).unwrap();
        let volume = catalog.create("database", 1 << 30).unwrap();
        assert_eq!(volume.allocated_bytes, 0);
        let id = volume.metadata.id;
        let (_, _, mut disk) = catalog.read(&id).unwrap();
        disk.seek(SeekFrom::Start(4096)).unwrap();
        disk.write_all(b"committed data").unwrap();
        disk.sync_all().unwrap();
        drop((catalog, disk));
        let catalog = Catalog::open(&state).unwrap();
        assert_eq!(catalog.inspect("database").unwrap().metadata.id, id);
        assert_eq!(catalog.inspect(&id).unwrap().metadata.capacity_bytes, 1 << 30);
        assert!(catalog.create("database", 512).is_err());
        let (_, _, mut disk) = catalog.read(&id).unwrap();
        disk.seek(SeekFrom::Start(4096)).unwrap();
        let mut bytes = [0; 14];
        disk.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"committed data");
        drop(disk);
        catalog.remove(&id).unwrap();
        assert!(catalog.list().unwrap().is_empty());
    }

    #[test]
    fn catalog_operation_unlocks_before_an_inherited_child_execs() {
        use crate::test_util::JoinWithin;
        const CHILD: &str = "FLEXVM_TEST_CATALOG_FORK";
        if std::env::var_os(CHILD).is_none() {
            let status = crate::test_util::status(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "volume::tests::catalog_operation_unlocks_before_an_inherited_child_execs"])
                    .env(CHILD, "1"),
            )
            .unwrap();
            assert!(status.success(), "catalog fork helper: {status}");
            return;
        }
        // Isolate the fork from other tests, and release its pre-exec gate even
        // if the parent's assertion unwinds.
        struct Release(std::os::unix::net::UnixStream);
        impl Drop for Release {
            fn drop(&mut self) {
                let _ = self.0.write_all(b"r");
            }
        }
        let state = crate::test_util::TempDir::new("volume-catalog-fork");
        let catalog = Catalog::open(&state).unwrap();
        let operation = catalog.lock(libc::LOCK_EX).unwrap();
        let (parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
        parent.set_read_timeout(Some(crate::test_util::WAIT)).unwrap();
        child.set_read_timeout(Some(crate::test_util::WAIT)).unwrap();
        let mut release = Release(parent);
        let spawner = std::thread::spawn(move || {
            let fd = child.as_raw_fd();
            let mut command = Command::new("true");
            unsafe {
                command.pre_exec(move || {
                    if libc::write(fd, b"f".as_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let mut byte = 0u8;
                    if libc::read(fd, (&mut byte as *mut u8).cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            command.status()
        });
        release.0.read_exact(&mut [0]).unwrap();
        drop(operation);
        let result = catalog.create("after-fork", 512);
        drop(release);
        assert!(spawner.join_within().unwrap().unwrap().success());
        result.unwrap();
    }

    #[test]
    fn inherited_disk_lock_survives_owner_descriptor_close() {
        let state = crate::test_util::TempDir::new("volume-lease");
        let catalog = Catalog::open(&state).unwrap();
        let id = catalog.create("busy", 512).unwrap().metadata.id;
        let (_, _, disk) = catalog.read(&id).unwrap();
        crate::host::flock(&disk, libc::LOCK_EX | libc::LOCK_NB).unwrap();
        let fd = disk.as_raw_fd();
        let mut command = Command::new("sh");
        command.args(["-c", "printf .; read answer"]).stdin(Stdio::piped()).stdout(Stdio::piped());
        unsafe {
            command.pre_exec(move || util::check(libc::fcntl(fd, libc::F_SETFD, 0)));
        }
        let mut child = crate::test_util::ChildGuard(command.spawn().unwrap());
        let mut ready = [0];
        child.stdout.as_mut().unwrap().read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b".");
        drop(disk);
        assert!(catalog.remove("busy").unwrap_err().to_string().contains("still in use"));
        assert!(catalog.clone_volume("busy", "blocked-copy").unwrap_err().to_string().contains("still in use"));
        assert_eq!(catalog.inspect("busy").unwrap().metadata.id, id);
        child.stdin.take().unwrap().write_all(b"release\n").unwrap();
        crate::test_util::wait_until("volume lease helper exit", || child.try_wait().unwrap().is_some());
        assert!(child.wait().unwrap().success());
        catalog.remove("busy").unwrap();
    }

    #[test]
    fn sparse_clone_has_independent_identity_and_retained_bytes() {
        let state = crate::test_util::TempDir::new("volume-clone");
        let catalog = Catalog::open(&state).unwrap();
        let id = catalog.create("original", 1 << 30).unwrap().metadata.id;
        let (_, _, source) = catalog.read(&id).unwrap();
        source.write_all_at(b"first", 4096).unwrap();
        source.write_all_at(b"last", (1 << 30) - 4).unwrap();
        source.sync_all().unwrap();
        let cloned = catalog.clone_volume(&id, "copy").unwrap();
        assert_ne!(cloned.metadata.id, id);
        assert_eq!(cloned.metadata.capacity_bytes, 1 << 30);
        assert!(cloned.allocated_bytes < 16 << 20, "sparse clone allocated {}", cloned.allocated_bytes);
        let (_, _, copy) = catalog.read(&cloned.metadata.id).unwrap();
        assert_ne!(source.metadata().unwrap().ino(), copy.metadata().unwrap().ino());
        let mut bytes = [0; 5];
        copy.read_exact_at(&mut bytes, 4096).unwrap();
        assert_eq!(&bytes, b"first");
        copy.write_all_at(b"clone", 4096).unwrap();
        source.write_all_at(b"orig", (1 << 30) - 4).unwrap();
        copy.sync_all().unwrap();
        source.sync_all().unwrap();
        source.read_exact_at(&mut bytes, 4096).unwrap();
        assert_eq!(&bytes, b"first");
        let mut tail = [0; 4];
        copy.read_exact_at(&mut tail, (1 << 30) - 4).unwrap();
        assert_eq!(&tail, b"last");
        drop((source, copy, catalog));
        let catalog = Catalog::open(&state).unwrap();
        assert_eq!(catalog.inspect("copy").unwrap().metadata.id, cloned.metadata.id);
        assert!(catalog.clone_volume("original", "copy").is_err());
        assert!(catalog.clone_volume("original", "../outside").is_err());
        catalog.remove("original").unwrap();
        let (_, _, copy) = catalog.read(&cloned.metadata.id).unwrap();
        copy.read_exact_at(&mut bytes, 4096).unwrap();
        assert_eq!(&bytes, b"clone");
    }

    #[test]
    fn sparse_copy_fallback_preserves_holes_and_unpublished_failures_recover() {
        let state = crate::test_util::TempDir::new("volume-copy");
        let catalog = Catalog::open(&state).unwrap();
        let id = catalog.create("source", 32 << 20).unwrap().metadata.id;
        let (_, _, source) = catalog.read(&id).unwrap();
        source.write_all_at(b"head", 0).unwrap();
        source.write_all_at(b"tail", (32 << 20) - 4).unwrap();
        source.sync_all().unwrap();
        let _catalog = catalog.lock(libc::LOCK_EX).unwrap();
        let copy = catalog.create_locked("fallback", 32 << 20, |target| copy_sparse(&source, target, 32 << 20)).unwrap();
        assert!(copy.allocated_bytes < 4 << 20);
        let (_, _, target) = catalog.read(&copy.metadata.id).unwrap();
        let mut bytes = [0; 4];
        target.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"head");
        target.read_exact_at(&mut bytes, (32 << 20) - 4).unwrap();
        assert_eq!(&bytes, b"tail");
        target.read_exact_at(&mut bytes, 16 << 20).unwrap();
        assert_eq!(bytes, [0; 4]);
        let failed = catalog.create_locked("incomplete", 32 << 20, |target| {
            target.write_all_at(b"partial", 0)?;
            Err("injected copy failure".into())
        });
        assert!(failed.is_err());
        assert!(catalog.find("incomplete").is_err());
        catalog.recover().unwrap();
        assert!(!entries(&catalog.directory).unwrap().iter().any(|n| n.starts_with(".creating-")));
        catalog.create_locked("incomplete", 512, |_| Ok(())).unwrap();
    }

    #[test]
    fn recovery_finishes_retirement_and_abandons_unpublished_creates() {
        let state = crate::test_util::TempDir::new("volume-recovery");
        let catalog = Catalog::open(&state).unwrap();
        let id = catalog.create("retired", 512).unwrap().metadata.id;
        rename(&catalog.directory, &id, &format!(".deleting-v1-{id}")).unwrap();
        let staging = state.join("volumes/.creating-v1-0123456789abcdef0123456789abcdef");
        fs::create_dir(&staging).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();
        catalog.create("new", 512).unwrap();
        assert!(!staging.exists());
        assert!(!state.join(format!("volumes/.deleting-v1-{id}")).exists());
        assert_eq!(catalog.list().unwrap().len(), 1);
    }

    #[test]
    fn forged_members_and_unknown_deletion_contents_are_preserved() {
        let state = crate::test_util::TempDir::new("volume-forgery");
        let catalog = Catalog::open(&state).unwrap();
        let id = catalog.create("data", 512).unwrap().metadata.id;
        let raw = state.join(format!("volumes/{id}/disk.raw"));
        let outside = state.join("outside");
        fs::write(&outside, b"do not change").unwrap();
        fs::remove_file(&raw).unwrap();
        std::os::unix::fs::symlink(&outside, &raw).unwrap();
        assert!(catalog.inspect("data").is_err());
        assert!(catalog.clone_volume("data", "forged-copy").is_err());
        assert!(catalog.remove("data").is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"do not change");
        fs::remove_file(&raw).unwrap();
        let file = File::create(&raw).unwrap();
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600)).unwrap();
        file.set_len(512).unwrap();
        let unexpected = state.join(format!("volumes/{id}/future-generation"));
        fs::write(&unexpected, b"retain").unwrap();
        assert!(catalog.remove("data").is_err());
        assert!(unexpected.exists());
        assert_eq!(catalog.inspect("data").unwrap().metadata.id, id);
    }
}
