//! Private, content-verified software state. Manifests contain identities, never
//! paths: every artifact is opened relative to its pinned directory descriptor.
use std::collections::BTreeMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::util::Result;
use crate::{bail, util};

const MAX_MANIFEST: u64 = 8 << 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub architecture: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub id: String,
    pub offset: u64,
    pub claim: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub backend: String,
    pub vm_id: String,
    pub snapshot_id: String,
    pub identity_generation: u64,
    pub memory_mib: u32,
    pub vcpus: u32,
    pub paused: bool,
    pub terminal: bool,
    pub host_id: String,
    pub source_owner: crate::host::Ident,
    pub source_engine: crate::host::Ident,
    pub owner_generation: u64,
    pub saved_epoch: u64,
    pub barrier_generation: u64,
    pub barrier_sequence: u64,
    pub profile: Profile,
    pub engine_version: serde_json::Value,
    pub engine: Artifact,
    pub kernel: Artifact,
    pub rootfs: Artifact,
    pub state: Artifact,
    pub firmware: BTreeMap<String, Artifact>,
    pub main: Session,
    pub image: crate::image::ImageMeta,
}

impl Manifest {
    fn validate(&self) -> Result<()> {
        if [&self.vm_id, &self.snapshot_id, &self.host_id].iter().any(|id| id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
            || !self.terminal
            || self.identity_generation == 0
            || !(128..=1_048_576).contains(&self.memory_mib)
            || !(1..=256).contains(&self.vcpus)
            || self.barrier_generation > self.owner_generation
            || self.owner_generation == 0
            || self.barrier_sequence == 0
            || !crate::guest::valid_session_id(&self.main.id)
        {
            bail!("software state has invalid ownership, session or barrier identity");
        }
        if [&self.engine, &self.kernel, &self.rootfs, &self.state].iter().any(|artifact| artifact.bytes == 0) {
            bail!("software state has an empty artifact");
        }
        Ok(())
    }
}

/// A source descriptor and its identity at hashing time. Capture checks both
/// metadata changes and the copied content before publishing an artifact.
pub struct Input {
    pub file: File,
    pub artifact: Artifact,
    stamp: Stamp,
}

#[derive(PartialEq, Eq)]
struct Stamp(u64, u64, u64, i64, i64, i64, i64);

impl Stamp {
    fn of(m: &Metadata) -> Self {
        Self(m.dev(), m.ino(), m.len(), m.ctime(), m.ctime_nsec(), m.mtime(), m.mtime_nsec())
    }
}

impl Input {
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
        Self::read(file, None)
    }

    fn read(file: File, expected: Option<&Artifact>) -> Result<Self> {
        let before = file.metadata()?;
        if !before.is_file() {
            bail!("software artifact is not a regular file");
        }
        if expected.is_some_and(|expected| expected.bytes != before.len()) {
            bail!("software artifact length does not match its manifest");
        }
        let stamp = Stamp::of(&before);
        let mut hash = Sha256::new();
        let mut offset = 0;
        let mut buf = vec![0; 1 << 20];
        while offset < before.len() {
            crate::template::interrupted()?;
            let wanted = (before.len() - offset).min(buf.len() as u64) as usize;
            let n = file.read_at(&mut buf[..wanted], offset)?;
            if n == 0 {
                bail!("software artifact was truncated while hashing");
            }
            hash.update(&buf[..n]);
            offset += n as u64;
        }
        if stamp != Stamp::of(&file.metadata()?) || offset != before.len() {
            bail!("software artifact changed while hashing");
        }
        let artifact = Artifact { bytes: offset, sha256: format!("{:x}", hash.finalize()) };
        if expected.is_some_and(|expected| *expected != artifact) {
            bail!("software artifact content or length does not match its manifest");
        }
        Ok(Self { file, artifact, stamp })
    }

    pub fn unchanged(&self) -> Result<()> {
        if Stamp::of(&self.file.metadata()?) != self.stamp {
            bail!("software input changed since it was pinned");
        }
        Ok(())
    }

    fn copy_to(&self, path: &Path, executable: bool) -> Result<Artifact> {
        self.unchanged()?;
        let mut out = OpenOptions::new().write(true).read(true).create_new(true).mode(0o600).open(path)?;
        let mut offset = 0;
        let mut buf = vec![0; 1 << 20];
        while offset < self.artifact.bytes {
            crate::template::interrupted()?;
            let wanted = (self.artifact.bytes - offset).min(buf.len() as u64) as usize;
            let n = self.file.read_at(&mut buf[..wanted], offset)?;
            if n == 0 {
                bail!("software input was truncated while copying");
            }
            out.write_all(&buf[..n])?;
            offset += n as u64;
        }
        self.unchanged()?;
        let verified = Self::read(out.try_clone()?, Some(&self.artifact))?;
        out.set_permissions(fs::Permissions::from_mode(if executable { 0o500 } else { 0o400 }))?;
        out.sync_all()?;
        Ok(verified.artifact)
    }
}

pub struct Inputs {
    pub engine: Input,
    pub kernel: Input,
    pub rootfs: Input,
    pub firmware: BTreeMap<String, Input>,
}

impl Inputs {
    pub fn open(engine: &str, kernel: &Path, rootfs: &Path) -> Result<Self> {
        let engine = if engine.contains('/') {
            PathBuf::from(engine)
        } else {
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|dir| dir.join(engine))
                .find(|path| path.is_file())
                .ok_or("software engine not found in PATH")?
        };
        let engine = Input::open(&engine.canonicalize()?)?;
        let firmware = discover_firmware(&engine)?;
        Ok(Self { engine, kernel: Input::open(&kernel.canonicalize()?)?, rootfs: Input::open(&rootfs.canonicalize()?)?, firmware })
    }
}

fn firmware_names() -> &'static [&'static str] {
    if std::env::consts::ARCH == "x86_64" {
        &["bios-256k.bin", "kvmvapic.bin", "pvh.bin", "linuxboot_dma.bin", "vgabios-stdvga.bin", "efi-virtio.rom"]
    } else {
        &[]
    }
}

fn discover_firmware(engine: &Input) -> Result<BTreeMap<String, Input>> {
    if firmware_names().is_empty() {
        return Ok(BTreeMap::new());
    }
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(crate::host::fd_path(engine.file.as_raw_fd()));
    command.args(["-L", "help"]);
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::other("software owner exited during firmware discovery"));
            }
            Ok(())
        });
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let output = util::run_until(&mut command, || {
        crate::template::interrupted()?;
        if std::time::Instant::now() >= deadline {
            bail!("software firmware discovery timed out");
        }
        Ok(())
    })?;
    if !output.status.success() || output.stdout.len() > 65536 {
        bail!("software engine did not report its firmware search paths");
    }
    engine.unchanged()?;
    let paths: Vec<_> = std::str::from_utf8(&output.stdout)?.lines().map(PathBuf::from).collect();
    firmware_names()
        .iter()
        .map(|name| {
            let path =
                paths.iter().map(|dir| dir.join(name)).find(|path| path.is_file()).ok_or_else(|| format!("software engine firmware {name} was not found"))?;
            Ok((name.to_string(), Input::open(&path.canonicalize()?)?))
        })
        .collect::<Result<_>>()
}

/// A completed set of verified open files. QEMU must receive these descriptors;
/// reopening any manifest-selected pathname would discard the verification.
pub struct Verified {
    pub manifest: Manifest,
    pub inputs: Inputs,
    pub state: Input,
    _directory: File,
}

fn private_directory(path: &Path) -> Result<File> {
    owned_directory(path, 0o077)
}

fn parent_directory(path: &Path) -> Result<File> {
    owned_directory(path, 0o022)
}

fn owned_directory(path: &Path, forbidden: u32) -> Result<File> {
    let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)?;
    let stat = dir.metadata()?;
    if stat.uid() != unsafe { libc::geteuid() } || stat.mode() & forbidden != 0 {
        bail!("software state directory is not private to its owner");
    }
    Ok(dir)
}

fn member(dir: &File, name: &str) -> Result<File> {
    let fd = unsafe {
        libc::openat(dir.as_raw_fd(), util::cpath(Path::new(name))?.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    use std::os::fd::FromRawFd;
    let file = unsafe { File::from_raw_fd(fd) };
    let stat = file.metadata()?;
    if !stat.is_file() || stat.uid() != unsafe { libc::geteuid() } || stat.mode() & 0o222 != 0 || stat.nlink() != 1 {
        bail!("software artifact is not an immutable private regular file");
    }
    Ok(file)
}

pub fn identifies(path: &Path) -> bool {
    fs::symlink_metadata(path.join("SOFTWARE")).is_ok_and(|metadata| metadata.is_file())
}

fn read_manifest(dir: &File) -> Result<Manifest> {
    let mut marker = Vec::new();
    member(dir, "SOFTWARE")?.take(64).read_to_end(&mut marker)?;
    if marker != b"flexvm-qemu-state-1\n" {
        bail!("unsupported software state marker");
    }
    let mut bytes = Vec::new();
    member(dir, "manifest.json")?.take(MAX_MANIFEST + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST {
        bail!("software state manifest is too large");
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    if manifest.format != 1 || manifest.backend != "qemu-tcg" {
        bail!("unsupported software state format or backend");
    }
    manifest.validate()?;
    let mut owner = Vec::new();
    member(dir, "OWNER")?.take(4096).read_to_end(&mut owner)?;
    if serde_json::from_slice::<crate::host::Ident>(&owner)? != manifest.source_owner {
        bail!("software checkpoint owner identity does not match");
    }
    let names: std::collections::BTreeSet<_> = manifest.firmware.keys().map(String::as_str).collect();
    let expected: std::collections::BTreeSet<_> = firmware_names().iter().copied().collect();
    if names != expected {
        bail!("software state firmware set does not match this architecture profile");
    }
    Ok(manifest)
}

pub fn metadata(path: &Path) -> Result<Manifest> {
    read_manifest(&private_directory(path)?)
}

pub fn open(path: &Path, profile: &Profile) -> Result<Verified> {
    let dir = private_directory(path)?;
    let manifest = read_manifest(&dir)?;
    if manifest.profile != *profile {
        bail!("software state execution profile does not match");
    }
    Ok(Verified {
        inputs: Inputs {
            engine: Input::read(member(&dir, "engine")?, Some(&manifest.engine))?,
            kernel: Input::read(member(&dir, "kernel")?, Some(&manifest.kernel))?,
            rootfs: Input::read(member(&dir, "rootfs")?, Some(&manifest.rootfs))?,
            firmware: manifest
                .firmware
                .iter()
                .map(|(name, artifact)| Ok((name.clone(), Input::read(member(&dir, &format!("firmware-{name}"))?, Some(artifact))?)))
                .collect::<Result<_>>()?,
        },
        state: Input::read(member(&dir, "state")?, Some(&manifest.state))?,
        manifest,
        _directory: dir,
    })
}

fn present(dir: &File, name: &str) -> Result<bool> {
    match fs::symlink_metadata(crate::host::fd_path(dir.as_raw_fd()).join(name)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn record<T: serde::de::DeserializeOwned>(dir: &File, name: &str) -> Result<T> {
    let mut bytes = Vec::new();
    member(dir, name)?.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        bail!("software ownership record is too large");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_record(dir: &File, name: &str, bytes: &[u8], replace: bool) -> Result<()> {
    let parent = crate::host::fd_path(dir.as_raw_fd());
    let temporary = parent.join(format!(".record-{}", util::random_hex(16)?));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)?;
        file.write_all(bytes)?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        let target = parent.join(name);
        if replace {
            fs::rename(&temporary, target)?;
        } else if !util::rename_noreplace(&temporary, &target)? {
            return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into());
        }
        dir.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub fn host_id(state: &Path) -> Result<String> {
    let dir = parent_directory(state)?;
    if !present(&dir, ".software-host-id")? {
        let id = util::random_hex(16)?;
        match write_record(&dir, ".software-host-id", &serde_json::to_vec(&id)?, false) {
            Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) => {}
            result => result?,
        }
    }
    let id: String = record(&dir, ".software-host-id")?;
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid software host identity");
    }
    Ok(id)
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retirement {
    manifest_sha256: String,
    snapshot_id: String,
    vm_id: String,
    host_id: String,
    generation: u64,
    owner: crate::host::Ident,
    engine: crate::host::Ident,
}

impl Retirement {
    fn of(manifest: &Manifest) -> Result<Self> {
        Ok(Self {
            manifest_sha256: format!("{:x}", Sha256::digest(serde_json::to_vec(manifest)?)),
            snapshot_id: manifest.snapshot_id.clone(),
            vm_id: manifest.vm_id.clone(),
            host_id: manifest.host_id.clone(),
            generation: manifest.owner_generation,
            owner: manifest.source_owner.clone(),
            engine: manifest.source_engine.clone(),
        })
    }
}

pub struct Published {
    directory: File,
    pub manifest: Manifest,
}

impl Published {
    /// A local retirement receipt is written only after its actual engine has
    /// exited. Cross-host authority requires the separate signed transfer protocol.
    pub fn retire(&self) -> Result<()> {
        if self.manifest.source_owner != crate::host::Ident::me() {
            bail!("software checkpoint was not captured by this owner");
        }
        if crate::host::PidFd::open(&self.manifest.source_engine)?.is_some() {
            bail!("software source engine is still alive");
        }
        write_record(&self.directory, "RETIRED", &serde_json::to_vec(&Retirement::of(&self.manifest)?)?, false)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    manifest_sha256: String,
    snapshot_id: String,
    generation: u64,
    owner: crate::host::Ident,
    engine: crate::host::Ident,
}

pub struct Prepared<'a> {
    directory: File,
    manifest: Manifest,
    pub generation: u64,
    _name: &'a crate::host::NameLock,
}

pub struct Consumed {
    directory: File,
    grant: Grant,
    manifest: Manifest,
}

impl Verified {
    /// Reserve a generation while the ordinary VM name lock is held. No engine
    /// may execute until Prepared::grant durably commits its exact identity.
    pub fn prepare<'a>(&self, name: &'a crate::host::NameLock, local_host: &str) -> Result<Prepared<'a>> {
        let dir = &self._directory;
        if self.manifest.host_id != local_host {
            bail!("software checkpoint belongs to another host; cross-host transfer is not enabled");
        }
        if present(dir, "DISCARDED")? {
            bail!("software checkpoint was discarded");
        }
        if present(dir, "STARTED")? {
            bail!("software checkpoint already granted execution; it remains quarantined and cannot be replayed by start");
        }
        let expected = Retirement::of(&self.manifest)?;
        if present(dir, "RETIRED")? {
            if record::<Retirement>(dir, "RETIRED")? != expected {
                bail!("software retirement does not match this checkpoint");
            }
        } else {
            if crate::host::PidFd::open(&self.manifest.source_owner)?.is_some() {
                bail!("software source owner has not retired");
            }
            if crate::host::PidFd::open(&self.manifest.source_engine)?.is_some() {
                bail!("software source engine has not retired");
            }
            // Recover the commit-before-retirement crash window on this host.
            write_record(dir, "RETIRED", &serde_json::to_vec(&expected)?, false)?;
        }
        if crate::host::PidFd::open(&self.manifest.source_engine)?.is_some() {
            bail!("retired software source engine is still alive");
        }
        let highest = if present(dir, "HIGHEST")? { record::<u64>(dir, "HIGHEST")? } else { self.manifest.owner_generation };
        let generation = highest.max(self.manifest.owner_generation).checked_add(1).ok_or("software owner generation exhausted")?;
        write_record(dir, "HIGHEST", &serde_json::to_vec(&generation)?, true)?;
        Ok(Prepared { directory: dir.try_clone()?, manifest: self.manifest.clone(), generation, _name: name })
    }
}

impl Prepared<'_> {
    pub fn grant(self, engine: crate::host::Ident) -> Result<Consumed> {
        if record::<u64>(&self.directory, "HIGHEST")? != self.generation {
            bail!("software owner preparation was superseded");
        }
        if present(&self.directory, "DISCARDED")? {
            bail!("software checkpoint was discarded during restore");
        }
        if crate::host::PidFd::open(&engine)?.is_none() {
            bail!("software destination engine exited before its ownership grant");
        }
        let grant = Grant {
            manifest_sha256: Retirement::of(&self.manifest)?.manifest_sha256,
            snapshot_id: self.manifest.snapshot_id.clone(),
            generation: self.generation,
            owner: crate::host::Ident::me(),
            engine,
        };
        write_record(&self.directory, "STARTED", &serde_json::to_vec(&grant)?, false)?;
        Ok(Consumed { directory: self.directory, grant, manifest: self.manifest })
    }
}

impl Consumed {
    fn check_replacement(&self, path: &Path, new: &Manifest) -> Result<()> {
        let target = private_directory(path)?;
        let (selected, pinned) = (target.metadata()?, self.directory.metadata()?);
        if (selected.dev(), selected.ino()) != (pinned.dev(), pinned.ino())
            || record::<Grant>(&self.directory, "STARTED")? != self.grant
            || self.grant.owner != crate::host::Ident::me()
            || new.source_owner != self.grant.owner
            || new.source_engine != self.grant.engine
            || new.owner_generation != self.grant.generation
            || new.vm_id != self.manifest.vm_id
        {
            bail!("software checkpoint replacement does not belong to this live owner");
        }
        Ok(())
    }
}

pub fn retired_for(path: &Path, owner: &crate::host::Ident, local_host: &str) -> Result<bool> {
    let dir = private_directory(path)?;
    let manifest = read_manifest(&dir)?;
    if manifest.source_owner != *owner || manifest.host_id != local_host || present(&dir, "DISCARDED")? || present(&dir, "STARTED")? {
        return Ok(false);
    }
    Ok(present(&dir, "RETIRED")? && record::<Retirement>(&dir, "RETIRED")? == Retirement::of(&manifest)?)
}

pub fn remove_discarded(path: &Path, vm_id: &str) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let dir = private_directory(path)?;
    if present(&dir, "DISCARDED")? {
        let manifest = read_manifest(&dir)?;
        if manifest.vm_id != vm_id || manifest.source_owner != crate::host::Ident::me() {
            bail!("discarded software checkpoint belongs to another owner");
        }
        fs::remove_dir_all(path)?;
        util::sync_dir(path.parent().ok_or("software checkpoint has no parent")?)?;
    }
    Ok(())
}

/// Invalidate only this attempted snapshot before authorizing source rollback.
pub fn discard_attempt(path: &Path, snapshot_id: &str) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let dir = private_directory(path)?;
    let manifest = read_manifest(&dir)?;
    if manifest.snapshot_id != snapshot_id {
        return Ok(());
    }
    if manifest.source_owner != crate::host::Ident::me() || present(&dir, "STARTED")? || present(&dir, "RETIRED")? {
        bail!("software source cannot roll back a retired or transferred checkpoint");
    }
    if !present(&dir, "DISCARDED")? {
        write_record(&dir, "DISCARDED", b"discarded\n", false)?;
    }
    Ok(())
}

pub fn describe(path: &Path, name: &str) -> Result<serde_json::Value> {
    let dir = private_directory(path)?;
    let manifest = read_manifest(&dir)?;
    let grant = if present(&dir, "STARTED")? { Some(record::<Grant>(&dir, "STARTED")?) } else { None };
    let process = grant.as_ref().map_or_else(|| manifest.source_engine.clone(), |grant| grant.engine.clone());
    let owner = grant.as_ref().map_or_else(|| manifest.source_owner.clone(), |grant| grant.owner.clone());
    let entry = crate::host::Entry {
        name: name.into(),
        ident: owner,
        backend: crate::host::Backend::QemuTcg {
            process,
            image: manifest.image.source,
            digest: manifest.image.digest,
            argv: manifest.image.argv,
            ram_mib: manifest.memory_mib,
        },
        ip: Some("169.254.1.2".parse()?),
        gen: manifest.identity_generation,
        vcpus: manifest.vcpus,
        max_mib: u64::from(manifest.memory_mib),
        cmd: true,
        state: if grant.is_some() { "quarantined" } else { "suspended" }.into(),
        ..Default::default()
    };
    let mut value = serde_json::to_value(entry)?;
    value["checkpoint_mib"] = serde_json::json!(manifest.state.bytes.div_ceil(1 << 20));
    value["snapshot_id"] = serde_json::json!(manifest.snapshot_id);
    if grant.is_some() {
        value["error"] = serde_json::json!("checkpoint already granted execution; recovery is required before replay");
    }
    Ok(value)
}

/// Staging is private and never overwrites a committed directory. The caller
/// serializes name/generation ownership and decides when to publish this snapshot.
pub struct Staging {
    path: PathBuf,
    pub state: File,
    committed: bool,
    parent: File,
}

impl Staging {
    pub fn new(parent: &Path) -> Result<Self> {
        let parent = parent_directory(parent)?;
        let path = crate::host::fd_path(parent.as_raw_fd()).join(format!(".software-stage-{}", util::random_hex(16)?));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        let state = match OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(path.join("state")) {
            Ok(state) => state,
            Err(error) => {
                let _ = fs::remove_dir(&path);
                return Err(error.into());
            }
        };
        Ok(Self { path, state, committed: false, parent })
    }

    pub fn commit(self, destination: &Path, inputs: &Inputs, manifest: Manifest) -> Result<Published> {
        self.publish(destination, inputs, manifest, None)
    }

    pub fn replace(self, destination: &Path, inputs: &Inputs, manifest: Manifest, previous: &Consumed) -> Result<Published> {
        self.publish(destination, inputs, manifest, Some(previous))
    }

    fn publish(mut self, destination: &Path, inputs: &Inputs, mut manifest: Manifest, previous: Option<&Consumed>) -> Result<Published> {
        let selected_parent = parent_directory(destination.parent().ok_or("software checkpoint has no parent")?)?;
        let (selected, pinned) = (selected_parent.metadata()?, self.parent.metadata()?);
        if (selected.dev(), selected.ino()) != (pinned.dev(), pinned.ino()) {
            bail!("software checkpoint destination has a different parent");
        }
        let target = crate::host::fd_path(self.parent.as_raw_fd()).join(destination.file_name().ok_or("software checkpoint has no name")?);
        if let Some(previous) = previous {
            previous.check_replacement(&target, &manifest)?;
        }
        manifest.engine = inputs.engine.copy_to(&self.path.join("engine"), true)?;
        manifest.kernel = inputs.kernel.copy_to(&self.path.join("kernel"), false)?;
        manifest.rootfs = inputs.rootfs.copy_to(&self.path.join("rootfs"), false)?;
        manifest.firmware = inputs
            .firmware
            .iter()
            .map(|(name, input)| {
                if !firmware_names().contains(&name.as_str()) {
                    bail!("unknown software firmware artifact");
                }
                Ok((name.clone(), input.copy_to(&self.path.join(format!("firmware-{name}")), false)?))
            })
            .collect::<Result<_>>()?;
        manifest.state = Input::read(self.state.try_clone()?, None)?.artifact;
        self.state.set_permissions(fs::Permissions::from_mode(0o400))?;
        self.state.sync_all()?;
        let directory = private_directory(&self.path)?;
        write_record(&directory, "SOFTWARE", b"flexvm-qemu-state-1\n", false)?;
        write_record(&directory, "OWNER", &serde_json::to_vec(&manifest.source_owner)?, false)?;
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(self.path.join("manifest.json"))?;
        manifest.validate()?;
        let bytes = serde_json::to_vec(&manifest)?;
        if bytes.len() as u64 > MAX_MANIFEST {
            bail!("software state manifest is too large");
        }
        file.write_all(&bytes)?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        util::sync_dir(&self.path)?;
        if previous.is_some() {
            let (from, to) = (util::cpath(&self.path)?, util::cpath(&target)?);
            if unsafe { libc::renameat2(libc::AT_FDCWD, from.as_ptr(), libc::AT_FDCWD, to.as_ptr(), libc::RENAME_EXCHANGE) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        } else if !util::rename_noreplace(&self.path, &target)? {
            bail!("software checkpoint destination already exists");
        }
        self.committed = true;
        self.parent.sync_all()?;
        if previous.is_some() {
            let _ = fs::remove_dir_all(&self.path);
        }
        Ok(Published { directory, manifest })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;
    use serde_json::json;

    fn source(dir: &Path, name: &str, bytes: &[u8]) -> Input {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        Input::open(&path).unwrap()
    }

    fn manifest(profile: Profile) -> Manifest {
        let blank = Artifact { bytes: 0, sha256: String::new() };
        Manifest {
            format: 1,
            backend: "qemu-tcg".into(),
            vm_id: "0123456789abcdef0123456789abcdef".into(),
            snapshot_id: "abcdef0123456789abcdef0123456789".into(),
            identity_generation: 1,
            memory_mib: 512,
            vcpus: 1,
            paused: false,
            terminal: true,
            host_id: "00000000000000000000000000000000".into(),
            source_owner: crate::host::Ident::me(),
            source_engine: {
                let mut id = crate::host::Ident::me();
                id.pid = i32::MAX as u32;
                id
            },
            owner_generation: 7,
            saved_epoch: 42,
            barrier_generation: 7,
            barrier_sequence: 3,
            profile,
            engine_version: json!({"qemu":{"major":10,"minor":2,"micro":1}}),
            engine: blank.clone(),
            kernel: blank.clone(),
            rootfs: blank.clone(),
            state: blank,
            firmware: BTreeMap::new(),
            main: Session { id: "saved-main".into(), offset: 19, claim: 2 },
            image: serde_json::from_value(json!({"source":"local", "digest":"sha256:image", "config_digest":"sha256:config",
                "app_conf":"", "argv":["/probe"], "warm":false}))
            .unwrap(),
        }
    }

    fn checkpoint(dir: &Path) -> (PathBuf, Profile) {
        let inputs = Inputs {
            engine: source(dir, "source-engine", b"engine"),
            kernel: source(dir, "source-kernel", b"kernel"),
            rootfs: source(dir, "source-rootfs", b"rootfs"),
            firmware: firmware_names().iter().map(|name| (name.to_string(), source(dir, &format!("source-{name}"), name.as_bytes()))).collect(),
        };
        let profile = Profile { architecture: std::env::consts::ARCH.into(), arguments: vec!["native-profile".into()] };
        let mut staging = Staging::new(dir).unwrap();
        staging.state.write_all(b"saved-state").unwrap();
        let path = dir.join("checkpoint");
        staging.commit(&path, &inputs, manifest(profile.clone())).unwrap().retire().unwrap();
        (path, profile)
    }

    #[test]
    fn retirement_binds_the_complete_manifest() {
        let root = TempDir::new("software-artifact-receipt");
        let (path, profile) = checkpoint(&root);
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let name = host.take_name("vm", false).unwrap();
        let file = path.join("manifest.json");
        let mut manifest: Manifest = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        manifest.image.digest = "sha256:changed-metadata".into();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&file, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        let verified = open(&path, &profile).unwrap();
        assert!(verified.prepare(&name, &manifest.host_id).err().unwrap().to_string().contains("retirement does not match"));
    }

    #[test]
    fn aborted_preparations_never_reuse_generations_and_only_latest_can_grant() {
        let root = TempDir::new("software-artifact-grants");
        let (path, profile) = checkpoint(&root);
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let name = host.take_name("vm", false).unwrap();
        let verified = open(&path, &profile).unwrap();
        let first = verified.prepare(&name, &verified.manifest.host_id).unwrap();
        assert_eq!(first.generation, 8);
        let latest = verified.prepare(&name, &verified.manifest.host_id).unwrap();
        assert_eq!(latest.generation, 9);
        assert!(first.grant(crate::host::Ident::me()).err().unwrap().to_string().contains("superseded"));
        let consumed = latest.grant(crate::host::Ident::me()).unwrap();
        assert_eq!(consumed.grant.generation, 9);
        assert!(verified.prepare(&name, &verified.manifest.host_id).err().unwrap().to_string().contains("already granted"));
    }

    #[test]
    fn foreign_hosts_and_live_unretired_sources_cannot_authorize_execution() {
        let root = TempDir::new("software-artifact-authority");
        let (path, profile) = checkpoint(&root);
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let name = host.take_name("vm", false).unwrap();
        let verified = open(&path, &profile).unwrap();
        assert!(verified.prepare(&name, "11111111111111111111111111111111").err().unwrap().to_string().contains("another host"));
        fs::remove_file(path.join("RETIRED")).unwrap();
        assert!(verified.prepare(&name, &verified.manifest.host_id).err().unwrap().to_string().contains("source owner has not retired"));
        assert!(!path.join("STARTED").exists());
    }

    #[test]
    fn only_the_consuming_owner_can_atomically_replace_its_old_checkpoint() {
        let root = TempDir::new("software-artifact-replace");
        let (path, profile) = checkpoint(&root);
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let name = host.take_name("vm", false).unwrap();
        let verified = open(&path, &profile).unwrap();
        let consumed = verified.prepare(&name, &verified.manifest.host_id).unwrap().grant(crate::host::Ident::me()).unwrap();
        let inputs = Inputs {
            engine: source(&root, "next-engine", b"engine"),
            kernel: source(&root, "next-kernel", b"kernel"),
            rootfs: source(&root, "next-rootfs", b"rootfs"),
            firmware: firmware_names().iter().map(|n| (n.to_string(), source(&root, &format!("next-{n}"), n.as_bytes()))).collect(),
        };
        let mut next = manifest(profile.clone());
        next.snapshot_id = "11111111111111111111111111111111".into();
        next.owner_generation = consumed.grant.generation;
        next.source_engine = crate::host::Ident::me();
        let mut staging = Staging::new(&root).unwrap();
        staging.state.write_all(b"next-state").unwrap();
        staging.replace(&path, &inputs, next, &consumed).unwrap();
        let new = open(&path, &profile).unwrap();
        assert_eq!(new.manifest.snapshot_id, "11111111111111111111111111111111");
        assert_eq!(new.manifest.owner_generation, 8);
        assert!(!path.join("STARTED").exists());
        assert!(!path.join("RETIRED").exists());
        assert!(new.prepare(&name, &new.manifest.host_id).is_err(), "the new source has not retired yet");
    }

    #[test]
    fn verified_descriptors_survive_path_replacement_and_keep_session_identity() {
        let root = TempDir::new("software-artifact-fds");
        let (path, profile) = checkpoint(&root);
        let verified = open(&path, &profile).unwrap();
        assert_eq!(verified.manifest.owner_generation, 7);
        assert_eq!(verified.manifest.main.offset, 19);
        fs::rename(&path, root.join("old")).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::write(path.join("kernel"), b"replacement").unwrap();
        let mut bytes = [0; 6];
        verified.inputs.kernel.file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"kernel");
        verified.inputs.kernel.unchanged().unwrap();
    }

    #[test]
    fn corrupted_and_truncated_artifacts_are_rejected_before_loading() {
        for (name, bytes) in [("kernel", &b"BROKEN"[..]), ("state", &b"short"[..])] {
            let root = TempDir::new("software-artifact-corrupt");
            let (path, profile) = checkpoint(&root);
            let file = path.join(name);
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&file, bytes).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
            let error = open(&path, &profile).err().unwrap().to_string();
            assert!(error.contains("does not match"), "{error}");
        }
    }

    #[test]
    fn symlinks_hardlinks_and_writable_artifacts_are_rejected() {
        for kind in ["symlink", "hardlink", "writable"] {
            let root = TempDir::new("software-artifact-links");
            let (path, profile) = checkpoint(&root);
            let file = path.join("state");
            match kind {
                "symlink" => {
                    fs::rename(&file, root.join("outside")).unwrap();
                    std::os::unix::fs::symlink(root.join("outside"), &file).unwrap();
                }
                "hardlink" => fs::hard_link(&file, root.join("outside")).unwrap(),
                _ => fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap(),
            }
            assert!(open(&path, &profile).is_err(), "accepted {kind}");
        }
    }

    #[test]
    fn incompatible_profiles_and_unknown_formats_never_load() {
        let root = TempDir::new("software-artifact-profile");
        let (path, profile) = checkpoint(&root);
        let mut other = profile.clone();
        other.arguments.push("changed-device".into());
        assert!(open(&path, &other).err().unwrap().to_string().contains("profile does not match"));
        let file = path.join("manifest.json");
        let mut changed: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        changed["format"] = json!(2);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&file, serde_json::to_vec(&changed).unwrap()).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(open(&path, &profile).err().unwrap().to_string().contains("unsupported software state"));
    }

    #[test]
    fn a_failed_commit_preserves_the_previous_checkpoint_and_cleans_staging() {
        let root = TempDir::new("software-artifact-publication");
        let (path, profile) = checkpoint(&root);
        let before = fs::read(path.join("manifest.json")).unwrap();
        let inputs = Inputs {
            engine: source(&root, "new-engine", b"new-engine"),
            kernel: source(&root, "new-kernel", b"new-kernel"),
            rootfs: source(&root, "new-rootfs", b"new-rootfs"),
            firmware: firmware_names().iter().map(|name| (name.to_string(), source(&root, &format!("new-{name}"), name.as_bytes()))).collect(),
        };
        let mut staging = Staging::new(&root).unwrap();
        staging.state.write_all(b"new-state").unwrap();
        assert!(staging.commit(&path, &inputs, manifest(profile.clone())).is_err());
        assert_eq!(fs::read(path.join("manifest.json")).unwrap(), before);
        assert!(open(&path, &profile).is_ok());
        assert!(fs::read_dir(&*root).unwrap().all(|entry| !entry.unwrap().file_name().to_string_lossy().starts_with(".software-stage-")));
    }
}
