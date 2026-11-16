//! Kernel-bound module artifacts. Files stay pinned from validation through use.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::unpack::{self, Meta};
use crate::bail;
use crate::software_state::Input;
use crate::util::Result;

pub(super) const MAX_BYTES: u64 = 4 << 30;
pub(super) const MAX_ENTRIES: u64 = 200_000;
const MANIFEST: &str = "usr/lib/flexvm/kernel-modules.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub kernel_sha256: String,
    pub bundle_sha256: String,
    pub release: String,
    pub development: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    version: u32,
    architecture: String,
    pub release: String,
    pub development: bool,
    kernel_sha256: String,
    source_sha256: String,
    config_sha256: String,
    symbols_sha256: String,
    source_archive: Option<String>,
    modules: BTreeMap<String, String>,
}

pub struct Bundle {
    pub kernel: Input,
    input: Input,
    pub manifest: Manifest,
}

pub(super) fn path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() || path.components().any(|part| matches!(part, Component::ParentDir | Component::Prefix(_))) {
        bail!("kernel module archive path escapes its tree: {path:?}");
    }
    let path: PathBuf = path.components().filter(|part| !matches!(part, Component::CurDir)).collect();
    if path.as_os_str().as_encoded_bytes().len() >= libc::PATH_MAX as usize
        || path.components().any(|part| part.as_os_str().as_encoded_bytes().len() > libc::NAME_MAX as usize)
    {
        bail!("kernel module archive path exceeds Linux pathname limits");
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        bail!("kernel module archive path contains NUL");
    }
    Ok(path)
}

pub(super) fn shared_directory(path: &Path) -> bool {
    matches!(path.to_str(), Some("" | "lib" | "lib/modules" | "usr" | "usr/lib" | "usr/lib/flexvm" | "usr/src" | "usr/src/flexvm"))
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_release(release: &str) -> bool {
    !release.is_empty()
        && release.len() <= 64
        && release.as_bytes()[0].is_ascii_alphanumeric()
        && release.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

impl Identity {
    pub(super) fn check_kernel(&self, sha256: &str) -> Result<()> {
        if !digest(&self.kernel_sha256) || !digest(&self.bundle_sha256) || !valid_release(&self.release) {
            bail!("image kernel module identity is invalid");
        }
        if self.kernel_sha256 != sha256 {
            bail!("image kernel modules do not match the selected kernel");
        }
        Ok(())
    }
}

impl Bundle {
    pub fn open(kernel: &Path, bundle: &Path, development: Option<bool>) -> Result<Self> {
        let kernel = Input::open(&kernel.canonicalize()?)?;
        let input = Input::open(&bundle.canonicalize()?)?;
        if input.artifact.bytes > 512 << 20 {
            bail!("kernel module archive exceeds 512 MiB");
        }
        let mut manifest = None;
        let mut paths = BTreeSet::new();
        let mut files = BTreeMap::new();
        let mut links = Vec::new();
        let mut name_bytes = 0usize;
        visit(&input, |entry, metadata| {
            let name = path(&metadata.path)?;
            name_bytes = name_bytes.saturating_add(name.as_os_str().as_encoded_bytes().len());
            if let Some(target) = &metadata.link {
                name_bytes = name_bytes.saturating_add(target.as_os_str().as_encoded_bytes().len());
            }
            if name_bytes > 32 << 20 {
                bail!("kernel module archive pathname metadata exceeds 32 MiB");
            }
            let kind = entry.header().entry_type();
            if !paths.insert(name.clone()) {
                bail!("duplicate kernel module archive path {name:?}");
            }
            if shared_directory(&name) {
                if !kind.is_dir() {
                    bail!("kernel module archive replaces a shared directory: {name:?}");
                }
                return Ok(());
            }
            if !(kind.is_dir() || kind.is_file() || kind.is_symlink() || kind.is_hard_link()) {
                bail!("unsupported kernel module archive entry {name:?}");
            }
            if kind.is_symlink() || kind.is_hard_link() {
                links.push((name.clone(), kind.is_symlink(), metadata.link.ok_or("kernel module archive link has no target")?));
            }
            if name == Path::new(MANIFEST) {
                if !kind.is_file() || entry.size() > unpack::MAX_DOCUMENT {
                    bail!("invalid kernel module manifest");
                }
                manifest = Some(serde_json::from_reader::<_, Manifest>(entry)?);
            } else if kind.is_file() {
                // Hash payloads once during admission. Extraction hashes the
                // compressed stream again and checks its pinned identity.
                let mut hash = Sha256::new();
                let mut buffer = [0u8; 64 << 10];
                loop {
                    let count = entry.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    hash.update(&buffer[..count]);
                }
                files.insert(name, format!("{:x}", hash.finalize()));
            }
            Ok(())
        })?;
        let manifest = manifest.ok_or("kernel module archive has no manifest")?;
        if manifest.version != 1 || manifest.architecture != std::env::consts::ARCH || development.is_some_and(|expected| manifest.development != expected) {
            bail!("kernel module archive has an unsupported format, architecture or development profile");
        }
        if !valid_release(&manifest.release) {
            bail!("kernel module archive has an invalid kernel release");
        }
        if [&manifest.kernel_sha256, &manifest.source_sha256, &manifest.config_sha256, &manifest.symbols_sha256].iter().any(|value| !digest(value)) {
            bail!("kernel module archive has invalid content identities");
        }
        if manifest.kernel_sha256 != kernel.artifact.sha256 {
            bail!("kernel module archive does not match the selected kernel");
        }
        let prefix = PathBuf::from(format!("lib/modules/{}", manifest.release));
        let source = manifest.source_archive.as_ref().map(|name| path(Path::new(name))).transpose()?;
        for name in &paths {
            if shared_directory(name) || name == Path::new(MANIFEST) {
                continue;
            }
            if !name.starts_with(&prefix) && source.as_ref() != Some(name) {
                bail!("kernel module archive writes outside its release: {name:?}");
            }
        }
        // Entries may never traverse an archive link, regardless of tar order.
        // This keeps extraction's parent creation inside the fresh release tree.
        let link_paths: BTreeSet<_> = links.iter().map(|(name, _, _)| name.clone()).collect();
        for name in &paths {
            if name.ancestors().skip(1).any(|parent| link_paths.contains(parent)) {
                bail!("kernel module archive member traverses a link: {name:?}");
            }
        }
        for (name, symlink, target) in links {
            if target.is_absolute()
                || target.as_os_str().as_encoded_bytes().contains(&0)
                || target.as_os_str().as_encoded_bytes().len() >= libc::PATH_MAX as usize
                || target.components().any(|part| part.as_os_str().as_encoded_bytes().len() > libc::NAME_MAX as usize)
            {
                bail!("kernel module archive has an invalid link target: {name:?}");
            }
            let mut resolved = if symlink { name.parent().ok_or("kernel module link has no parent")?.to_path_buf() } else { PathBuf::new() };
            for part in target.components() {
                match part {
                    Component::Normal(value) => resolved.push(value),
                    Component::CurDir => continue,
                    Component::ParentDir if symlink && resolved != prefix => {
                        resolved.pop();
                    }
                    _ => bail!("kernel module archive link escapes its release: {name:?}"),
                }
                if (symlink && !resolved.starts_with(&prefix)) || link_paths.contains(&resolved) {
                    bail!("kernel module archive link escapes or traverses another link: {name:?}");
                }
            }
            if !resolved.starts_with(&prefix) {
                bail!("kernel module archive link escapes its release: {name:?}");
            }
        }
        let modules: BTreeMap<_, _> = files
            .iter()
            .filter(|(name, _)| name.extension().is_some_and(|extension| extension == "ko"))
            .map(|(name, hash)| Ok((name.to_str().ok_or("kernel module path is not UTF-8")?.to_owned(), hash.clone())))
            .collect::<Result<_>>()?;
        if modules != manifest.modules || manifest.modules.values().any(|value| !digest(value)) {
            bail!("kernel module payloads do not match their manifest");
        }
        let build = prefix.join("build");
        if manifest.development {
            let source = source.ok_or("kernel development archive has no source archive")?;
            if source.parent() != Some(Path::new("usr/src/flexvm")) || source.file_name().is_none() {
                bail!("kernel development source archive has an invalid path");
            }
            for (name, expected) in
                [(build.join(".config"), &manifest.config_sha256), (build.join("Module.symvers"), &manifest.symbols_sha256), (source, &manifest.source_sha256)]
            {
                if files.get(&name) != Some(expected) {
                    bail!("kernel development input does not match its manifest: {name:?}");
                }
            }
            for name in [
                "System.map",
                "vmlinux",
                "include/generated/autoconf.h",
                "scripts/basic/fixdep",
                "scripts/mod/modpost",
                "scripts/module.lds",
                "tools/bpf/resolve_btfids/resolve_btfids",
            ] {
                if !files.contains_key(&build.join(name)) {
                    bail!("kernel development archive is missing {name}");
                }
            }
            if std::env::consts::ARCH == "x86_64" && !files.contains_key(&build.join("tools/objtool/objtool")) {
                bail!("kernel development archive is missing objtool");
            }
        } else if source.is_some() || paths.iter().any(|name| name.starts_with(&build) || name == &prefix.join("source")) {
            bail!("runtime kernel module archive contains development inputs");
        }
        kernel.unchanged()?;
        Ok(Self { kernel, input, manifest })
    }

    pub fn unchanged(&self) -> Result<()> {
        self.kernel.unchanged()?;
        self.input.unchanged()
    }

    pub fn identity(&self) -> Identity {
        Identity {
            kernel_sha256: self.kernel.artifact.sha256.clone(),
            bundle_sha256: self.input.artifact.sha256.clone(),
            release: self.manifest.release.clone(),
            development: self.manifest.development,
        }
    }

    pub(super) fn visit(&self, visitor: impl FnMut(&mut tar::Entry<'_, &mut dyn Read>, Meta) -> Result<()>) -> Result<()> {
        self.kernel.unchanged()?;
        visit(&self.input, visitor)?;
        self.kernel.unchanged()
    }
}

fn visit(input: &Input, visitor: impl FnMut(&mut tar::Entry<'_, &mut dyn Read>, Meta) -> Result<()>) -> Result<()> {
    input.unchanged()?;
    let mut file = &input.file;
    file.seek(SeekFrom::Start(0))?;
    let mut compressed = unpack::Hashed::new(file);
    {
        let mut reader = unpack::decompress(&mut compressed)?.take(MAX_BYTES + 1);
        let mut count = 0;
        unpack::each_entry(&mut reader as &mut dyn Read, &mut count, MAX_ENTRIES, visitor)?;
        io::copy(&mut reader, &mut io::sink())?;
        if reader.limit() == 0 {
            bail!("kernel module archive exceeds its decompressed size limit");
        }
    }
    io::copy(&mut compressed, &mut io::sink())?;
    if compressed.n != input.artifact.bytes || compressed.digest() != format!("sha256:{}", input.artifact.sha256) {
        bail!("kernel module archive changed after admission");
    }
    input.unchanged()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::os::unix::fs::symlink;

    const RELEASE: &str = "6.1-test";
    const MODULE: &str = "lib/modules/6.1-test/test.ko";
    const BUILD: &str = "lib/modules/6.1-test/build/";
    type Entry = (String, tar::EntryType, Vec<u8>);

    fn sha(data: &[u8]) -> String {
        format!("{:x}", Sha256::digest(data))
    }

    fn fixture(development: bool, change: impl FnOnce(&mut Value, &mut Vec<Entry>)) -> (crate::test_util::TempDir, PathBuf, PathBuf) {
        let temp = crate::test_util::TempDir::new("kernel-bundle");
        let kernel = temp.join("vmlinux");
        std::fs::write(&kernel, b"selected kernel").unwrap();
        let mut manifest = json!({
            "version":1, "architecture":std::env::consts::ARCH, "release":RELEASE,
            "development":development, "kernel_sha256":sha(b"selected kernel"),
            "source_sha256":sha(b"source"), "config_sha256":sha(b"config"),
            "symbols_sha256":sha(b"symbols"), "source_archive":null,
            "modules":{MODULE:sha(b"module")},
        });
        let mut entries = vec![(MODULE.into(), tar::EntryType::Regular, b"module".to_vec())];
        if development {
            manifest["source_archive"] = json!("usr/src/flexvm/linux.tar.xz");
            entries.push(("usr/src/flexvm/linux.tar.xz".into(), tar::EntryType::Regular, b"source".to_vec()));
            for (name, data) in [(".config", b"config".as_slice()), ("Module.symvers", b"symbols".as_slice())] {
                entries.push((format!("{BUILD}{name}"), tar::EntryType::Regular, data.to_vec()));
            }
            for name in [
                "System.map",
                "vmlinux",
                "include/generated/autoconf.h",
                "scripts/basic/fixdep",
                "scripts/mod/modpost",
                "scripts/module.lds",
                "tools/bpf/resolve_btfids/resolve_btfids",
                "tools/objtool/objtool",
            ] {
                entries.push((format!("{BUILD}{name}"), tar::EntryType::Regular, b"prepared input".to_vec()));
            }
            entries.push((format!("lib/modules/{RELEASE}/source"), tar::EntryType::Symlink, b"build".to_vec()));
        }
        change(&mut manifest, &mut entries);
        entries.push((MANIFEST.into(), tar::EntryType::Regular, serde_json::to_vec(&manifest).unwrap()));
        let archive = temp.join("modules.tar.gz");
        let gzip = flate2::write::GzEncoder::new(std::fs::File::create(&archive).unwrap(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gzip);
        for (name, kind, data) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(kind);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            // Raw names deliberately allow hostile '..' input in rejection cases.
            assert!(name.len() < 100);
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            if kind.is_symlink() || kind.is_hard_link() {
                header.set_size(0);
                tar.append_link(&mut header, &name, std::str::from_utf8(&data).unwrap()).unwrap();
            } else {
                header.set_size(data.len() as u64);
                header.set_cksum();
                tar.append(&header, data.as_slice()).unwrap();
            }
        }
        tar.into_inner().unwrap().finish().unwrap();
        (temp, kernel, archive)
    }

    #[test]
    fn admission_checks_payloads_and_development_profile() {
        for development in [false, true] {
            let (_temp, kernel, archive) = fixture(development, |_, _| {});
            let bundle = Bundle::open(&kernel, &archive, Some(development)).unwrap();
            assert_eq!(bundle.identity().kernel_sha256, sha(b"selected kernel"));
            assert_eq!(bundle.identity().development, development);
            assert!(Bundle::open(&kernel, &archive, Some(!development)).is_err());
            assert!(Bundle::open(&kernel, &archive, None).is_ok());
        }
    }

    #[test]
    fn mismatched_kernel_and_module_payloads_are_refused() {
        let (_temp, kernel, archive) = fixture(false, |_, _| {});
        std::fs::write(&kernel, b"another kernel").unwrap();
        assert!(Bundle::open(&kernel, &archive, None).err().unwrap().to_string().contains("selected kernel"));
        let (_temp, kernel, archive) = fixture(false, |_, entries| entries[0].2 = b"substituted module".to_vec());
        assert!(Bundle::open(&kernel, &archive, None).err().unwrap().to_string().contains("payloads"));
    }

    #[test]
    fn missing_and_unlisted_modules_are_refused() {
        for extra in [false, true] {
            let (_temp, kernel, archive) = fixture(false, |_, entries| {
                if extra {
                    entries.push(("lib/modules/6.1-test/unlisted.ko".into(), tar::EntryType::Regular, b"extra".to_vec()));
                } else {
                    entries.clear();
                }
            });
            assert!(Bundle::open(&kernel, &archive, None).is_err());
        }
    }

    #[test]
    fn hostile_paths_links_and_duplicate_members_are_refused() {
        for (name, kind, data) in [
            ("lib/modules/6.1-test/../escape", tar::EntryType::Regular, b"data".as_slice()),
            ("etc/passwd", tar::EntryType::Regular, b"data".as_slice()),
            ("lib/modules/6.1-test/link", tar::EntryType::Symlink, b"../../../../etc".as_slice()),
            ("lib/modules/6.1-test/link", tar::EntryType::Symlink, b"/etc".as_slice()),
            (MODULE, tar::EntryType::Regular, b"module".as_slice()),
        ] {
            let (_temp, kernel, archive) = fixture(false, |_, entries| entries.push((name.into(), kind, data.to_vec())));
            assert!(Bundle::open(&kernel, &archive, None).is_err(), "accepted {name}");
        }
    }

    #[test]
    fn links_cannot_leave_then_reenter_or_traverse_another_link() {
        for target in ["../../../../../../lib/modules/6.1-test", &"x".repeat(256), &"a/".repeat(2048)] {
            let (_temp, kernel, archive) = fixture(false, |_, entries| {
                entries.push(("lib/modules/6.1-test/link".into(), tar::EntryType::Symlink, target.as_bytes().to_vec()));
            });
            assert!(Bundle::open(&kernel, &archive, None).is_err(), "accepted target {target}");
        }
        for reverse in [false, true] {
            let (_temp, kernel, archive) = fixture(false, |_, entries| {
                let mut additions = vec![
                    ("lib/modules/6.1-test/a/b/c/up".into(), tar::EntryType::Symlink, b"../../..".to_vec()),
                    ("lib/modules/6.1-test/a/b/c/up/escape".into(), tar::EntryType::Symlink, b"../../../../etc".to_vec()),
                ];
                if reverse {
                    additions.reverse();
                }
                entries.extend(additions);
            });
            assert!(Bundle::open(&kernel, &archive, None).is_err());
        }
        let (_temp, kernel, archive) = fixture(false, |_, entries| {
            entries.push(("lib/modules/6.1-test/link".into(), tar::EntryType::Symlink, b".".to_vec()));
            entries.push(("lib/modules/6.1-test/other".into(), tar::EntryType::Symlink, b"link/../escape".to_vec()));
        });
        assert!(Bundle::open(&kernel, &archive, None).is_err());
        let (_temp, kernel, archive) = fixture(false, |_, entries| {
            entries.push(("lib/modules/6.1-test/alias".into(), tar::EntryType::Symlink, b"test.ko".to_vec()));
        });
        assert!(Bundle::open(&kernel, &archive, None).is_ok());
    }

    #[test]
    fn injection_refuses_image_directory_aliases_without_changing_their_targets() {
        use std::os::unix::fs::PermissionsExt;
        for directory in ["usr", "usr/lib", "usr/src", "lib", "lib/modules", "usr/lib/flexvm", "usr/src/flexvm"] {
            let (temp, kernel, archive) = fixture(true, |_, _| {});
            let bundle = Bundle::open(&kernel, &archive, None).unwrap();
            let root = temp.join("root");
            std::fs::create_dir_all(root.join("etc")).unwrap();
            std::fs::set_permissions(root.join("etc"), std::fs::Permissions::from_mode(0o771)).unwrap();
            std::fs::write(root.join("etc/keep"), b"keep").unwrap();
            let alias = root.join(directory);
            std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
            symlink("/etc", &alias).unwrap();
            let mut filesystem = unpack::Root::open(&root, unpack::Limits::default()).unwrap();
            assert!(filesystem.apply_kernel_bundle(&bundle).is_err(), "accepted {directory}");
            assert_eq!(std::fs::read(root.join("etc/keep")).unwrap(), b"keep");
            assert_eq!(std::fs::metadata(root.join("etc")).unwrap().permissions().mode() & 0o777, 0o771);
            assert_eq!(std::fs::read_dir(root.join("etc")).unwrap().count(), 1);
        }
    }

    #[test]
    fn wrong_architecture_and_missing_generated_sdk_inputs_are_refused() {
        let (_temp, kernel, archive) = fixture(false, |manifest, _| manifest["architecture"] = json!("unsupported"));
        assert!(Bundle::open(&kernel, &archive, None).is_err());
        let (_temp, kernel, archive) = fixture(true, |_, entries| entries.retain(|(name, _, _)| !name.ends_with("scripts/mod/modpost")));
        assert!(Bundle::open(&kernel, &archive, None).err().unwrap().to_string().contains("modpost"));
        let (_temp, kernel, archive) = fixture(true, |manifest, _| manifest["config_sha256"] = json!(sha(b"wrong config")));
        assert!(Bundle::open(&kernel, &archive, None).is_err());
    }

    #[test]
    fn injection_preserves_merged_usr_and_replaces_only_the_matching_release() {
        let (temp, kernel, archive) = fixture(true, |_, _| {});
        let bundle = Bundle::open(&kernel, &archive, Some(true)).unwrap();
        let root = temp.join("root");
        std::fs::create_dir_all(root.join("usr/lib/modules/6.1-test")).unwrap();
        std::fs::create_dir_all(root.join("usr/lib/modules/other")).unwrap();
        symlink("usr/lib", root.join("lib")).unwrap();
        std::fs::create_dir_all(root.join("usr/src/flexvm")).unwrap();
        std::fs::write(root.join("usr/src/flexvm/stale"), b"stale").unwrap();
        std::fs::write(root.join("lib/modules/6.1-test/stale.ko"), b"stale").unwrap();
        std::fs::write(root.join("lib/modules/other/keep.ko"), b"keep").unwrap();
        let mut filesystem = unpack::Root::open(&root, unpack::Limits::default()).unwrap();
        filesystem.apply_kernel_bundle(&bundle).unwrap();
        assert_eq!(std::fs::read_link(root.join("lib")).unwrap(), Path::new("usr/lib"));
        assert_eq!(std::fs::read(root.join(MODULE)).unwrap(), b"module");
        assert!(!root.join("lib/modules/6.1-test/stale.ko").exists());
        assert_eq!(std::fs::read(root.join("lib/modules/other/keep.ko")).unwrap(), b"keep");
        assert_eq!(std::fs::read(root.join(format!("{BUILD}.config"))).unwrap(), b"config");
        assert!(!root.join("usr/src/flexvm/stale").exists());
    }

    #[test]
    fn replaced_or_modified_inputs_cannot_redirect_an_admitted_bundle() {
        let (temp, kernel, archive) = fixture(false, |_, _| {});
        let bundle = Bundle::open(&kernel, &archive, None).unwrap();
        let next = temp.join("next");
        std::fs::write(&next, b"another kernel").unwrap();
        std::fs::rename(next, &kernel).unwrap();
        use std::os::unix::fs::FileExt;
        let mut bytes = [0; 15];
        bundle.kernel.file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"selected kernel");
        std::fs::write(&archive, b"replacement archive").unwrap();
        assert!(bundle.unchanged().is_err());
    }
}
