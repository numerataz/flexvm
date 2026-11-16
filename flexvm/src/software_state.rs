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
    pub owner_generation: u64,
    pub saved_epoch: u64,
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
        if self.vm_id.len() != 32
            || !self.vm_id.bytes().all(|b| b.is_ascii_hexdigit())
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
    let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)?;
    let stat = dir.metadata()?;
    if stat.uid() != unsafe { libc::geteuid() } || stat.mode() & 0o077 != 0 {
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

pub fn open(path: &Path, profile: &Profile) -> Result<Verified> {
    let dir = private_directory(path)?;
    let mut bytes = Vec::new();
    member(&dir, "manifest.json")?.take(MAX_MANIFEST + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST {
        bail!("software state manifest is too large");
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    if manifest.format != 1 || manifest.backend != "qemu-tcg" {
        bail!("unsupported software state format or backend");
    }
    if manifest.profile != *profile {
        bail!("software state execution profile does not match");
    }
    manifest.validate()?;
    let names: std::collections::BTreeSet<_> = manifest.firmware.keys().map(String::as_str).collect();
    let expected: std::collections::BTreeSet<_> = firmware_names().iter().copied().collect();
    if names != expected {
        bail!("software state firmware set does not match this architecture profile");
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
        let parent = private_directory(parent)?;
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

    pub fn commit(mut self, destination: &Path, inputs: &Inputs, mut manifest: Manifest) -> Result<()> {
        let selected_parent = private_directory(destination.parent().ok_or("software checkpoint has no parent")?)?;
        let (selected, pinned) = (selected_parent.metadata()?, self.parent.metadata()?);
        if (selected.dev(), selected.ino()) != (pinned.dev(), pinned.ino()) {
            bail!("software checkpoint destination has a different parent");
        }
        let target = crate::host::fd_path(self.parent.as_raw_fd()).join(destination.file_name().ok_or("software checkpoint has no name")?);
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
        if !util::rename_noreplace(&self.path, &target)? {
            bail!("software checkpoint destination already exists");
        }
        self.committed = true;
        self.parent.sync_all()?;
        Ok(())
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
            owner_generation: 7,
            saved_epoch: 42,
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
        staging.commit(&path, &inputs, manifest(profile.clone())).unwrap();
        (path, profile)
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
