//! Ordered checkpoint stream. The manifest fixes the member names, sizes and
//! digests. There are no paths, links, or authority records in the byte stream.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    host_id_in, parent_directory, parent_lock, present, private_directory, read_fence, read_incoming, read_input, retired_checkpoint, Host, Offer, Status,
};
use crate::software_state::{firmware_names, member, read_manifest, write_record, Artifact, Manifest, Retirement, Staging, MAX_MANIFEST};
use crate::{
    bail,
    util::{self, Result},
};

const MAGIC: &[u8] = b"flexvm-software-bundle-v1\n";
const HEADER_LIMIT: u64 = MAX_MANIFEST + 4096;

pub(crate) mod activate;
pub(in crate::software_state) const INCOMING: &str = "software-incoming";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    offer: Offer,
    manifest: Manifest,
}

impl Header {
    fn check(&self, expected: &Offer) -> Result<()> {
        if &self.offer != expected
            || self.manifest.host_id != expected.source_host
            || self.manifest.vm_id != expected.vm_id
            || self.manifest.owner_generation >= expected.generation
            || Retirement::of(&self.manifest)?.manifest_sha256 != expected.manifest_sha256
        {
            bail!("software bundle does not match the prepared offer");
        }
        if self.manifest.format != 1 || self.manifest.backend != "qemu-tcg" || self.manifest.profile.architecture != std::env::consts::ARCH {
            bail!("software bundle has an incompatible format, engine or architecture");
        }
        self.manifest.validate()?;
        if !self.manifest.disks.is_empty() {
            bail!("software bundle needs managed disk transport support");
        }
        if self.manifest.firmware.len() != firmware_names().len() || firmware_names().iter().any(|name| !self.manifest.firmware.contains_key(*name)) {
            bail!("software bundle firmware set does not match this architecture profile");
        }
        Ok(())
    }

    fn members(&self) -> impl Iterator<Item = (String, &Artifact)> {
        let manifest = &self.manifest;
        [("engine".into(), &manifest.engine), ("kernel".into(), &manifest.kernel), ("rootfs".into(), &manifest.rootfs), ("state".into(), &manifest.state)]
            .into_iter()
            .chain(manifest.firmware.iter().map(|(name, artifact)| (format!("firmware-{name}"), artifact)))
    }

    fn bytes(&self, limit: u64) -> Result<u64> {
        self.members().try_fold(0u64, |total, (_, artifact)| {
            total.checked_add(artifact.bytes).filter(|sum| *sum <= limit).ok_or_else(|| "software bundle exceeds its byte limit".into())
        })
    }

    fn write(&self, writer: &mut dyn Write) -> Result<()> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() as u64 > HEADER_LIMIT {
            bail!("software bundle header is too large");
        }
        writer.write_all(MAGIC)?;
        writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
        writer.write_all(&bytes)?;
        Ok(())
    }

    fn read(reader: &mut dyn Read) -> Result<Self> {
        let mut magic = [0; MAGIC.len()];
        reader.read_exact(&mut magic)?;
        if magic != MAGIC {
            bail!("unsupported software bundle framing");
        }
        let mut length = [0; 4];
        reader.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length);
        if u64::from(length) > HEADER_LIMIT {
            bail!("software bundle header is too large");
        }
        let mut bytes = vec![0; length as usize];
        reader.read_exact(&mut bytes)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn copy(reader: &mut dyn Read, output: &mut dyn Write, artifact: &Artifact, buffer: &mut [u8]) -> Result<()> {
    let mut remaining = artifact.bytes;
    let mut digest = Sha256::new();
    while remaining != 0 {
        crate::template::interrupted()?;
        let size = remaining.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..size])?;
        digest.update(&buffer[..size]);
        output.write_all(&buffer[..size])?;
        remaining -= size as u64;
    }
    if format!("{:x}", digest.finalize()) != artifact.sha256 {
        bail!("software bundle artifact digest mismatch");
    }
    Ok(())
}

fn verify_member(file: &mut File, expected: &Artifact, buffer: &mut [u8]) -> Result<()> {
    if file.metadata()?.len() != expected.bytes {
        bail!("software bundle artifact length mismatch");
    }
    copy(file, &mut std::io::sink(), expected, buffer)
}

pub(crate) fn send(host: &Host, vm: &str, input: &Path, output: &mut dyn Write) -> Result<()> {
    let offer: Offer = read_input(input)?;
    offer.validate()?;
    let _name = host.take_name(vm, true)?;
    let state = parent_directory(&host.state)?;
    let checkpoint = private_directory(&host.suspended(vm)?)?;
    crate::host::flock(&checkpoint, libc::LOCK_SH)?;
    let header = {
        let _transfer = parent_lock(&state, libc::LOCK_EX)?;
        let (manifest, _) = retired_checkpoint(&checkpoint)?;
        if host_id_in(&state)? != offer.source_host || !read_fence(&state, &offer.vm_id)?.is_some_and(|fence| !fence.recovered && fence.offer == offer) {
            bail!("software bundle needs an exact fenced source");
        }
        let header = Header { offer, manifest };
        header.check(&header.offer)?;
        header
    };
    header.write(output)?;
    let mut buffer = vec![0; 1 << 20];
    for (name, artifact) in header.members() {
        let mut file = member(&checkpoint, &name)?;
        if file.metadata()?.len() != artifact.bytes {
            bail!("software bundle source artifact length mismatch: {name}");
        }
        copy(&mut file, output, artifact, &mut buffer)?;
    }
    output.flush()?;
    Ok(())
}

fn seal(file: &File, executable: bool) -> Result<()> {
    file.set_permissions(std::fs::Permissions::from_mode(if executable { 0o500 } else { 0o400 }))?;
    file.sync_all()?;
    Ok(())
}

fn stage_bundle(staging: &mut Staging, header: &Header, reader: &mut dyn Read, buffer: &mut [u8]) -> Result<()> {
    for (name, artifact) in header.members() {
        let mut file = if name == "state" {
            staging.state.try_clone()?
        } else {
            OpenOptions::new().write(true).create_new(true).mode(0o600).open(staging.path.join(&name))?
        };
        crate::checkpoint::export::reserve(&file, artifact.bytes)?;
        copy(reader, &mut file, artifact, buffer)?;
        seal(&file, name == "engine")?;
    }
    write_record(&staging.directory, "SOFTWARE", b"flexvm-qemu-state-1\n", false)?;
    write_record(&staging.directory, "OWNER", &serde_json::to_vec(&header.manifest.source_owner)?, false)?;
    let manifest = serde_json::to_vec(&header.manifest)?;
    if manifest.len() as u64 > MAX_MANIFEST {
        bail!("software bundle manifest is too large");
    }
    write_record(&staging.directory, "manifest.json", &manifest, false)?;
    write_record(&staging.directory, "OFFER", &serde_json::to_vec(&header.offer)?, false)?;
    staging.directory.sync_all()?;
    Ok(())
}

fn receive(state: &Path, expected: &Offer, reader: &mut dyn Read, limit: u64) -> Result<u64> {
    let state = parent_directory(state)?;
    {
        let _transfer = parent_lock(&state, libc::LOCK_EX)?;
        super::require_incoming(&state, expected)?;
    }
    let header = Header::read(reader)?;
    header.check(expected)?;
    let bytes = header.bytes(limit)?;

    let incoming_path = crate::host::fd_path(state.as_raw_fd()).join(INCOMING);
    crate::host::host_dir(&incoming_path, 0o700)?;
    let incoming = private_directory(&incoming_path)?;
    state.sync_all()?;
    let incoming_path = crate::host::fd_path(incoming.as_raw_fd());
    let name = bundle_name(expected);
    let _bundle = crate::host::lock_at(crate::host::host_locks()?, &bundle_key(&incoming, &name)?, libc::LOCK_EX)?;
    let target = incoming_path.join(&name);
    let mut buffer = vec![0; 1 << 20];
    let staging = if present(&incoming, &name)? {
        let existing = private_directory(&target)?;
        crate::host::flock(&existing, libc::LOCK_SH)?;
        if super::record::<Offer>(&existing, "OFFER")? != *expected || Retirement::of(&read_manifest(&existing)?)?.manifest_sha256 != expected.manifest_sha256 {
            bail!("existing software bundle differs from the prepared offer");
        }
        for (name, artifact) in header.members() {
            copy(reader, &mut std::io::sink(), artifact, &mut buffer)?;
            verify_member(&mut member(&existing, &name)?, artifact, &mut buffer)?;
        }
        None
    } else {
        // Staging::new rejects a symlink at its last path component.
        let mut staging = Staging::new(&incoming_path.join("."))?;
        stage_bundle(&mut staging, &header, reader, &mut buffer)?;
        Some(staging)
    };
    if reader.read(&mut [0u8; 1])? != 0 {
        bail!("software bundle has trailing data");
    }
    let _transfer = parent_lock(&state, libc::LOCK_EX)?;
    super::require_incoming(&state, expected)?;
    if let Some(mut staging) = staging {
        let _publish = parent_lock(&incoming, libc::LOCK_EX)?;
        if !util::rename_noreplace(&staging.path, &target)? {
            bail!("software bundle appeared during publication");
        }
        staging.committed = true;
    }
    incoming.sync_all()?;
    Ok(bytes)
}

fn bundle_name(offer: &Offer) -> String {
    format!("{}-{}", offer.vm_id, offer.transfer_id)
}

fn bundle_key(incoming: &File, name: &str) -> std::io::Result<String> {
    Ok(crate::host::keyed("software-bundle", &util::fstat(incoming.as_raw_fd())?, name))
}

pub(in crate::software_state) fn sweep_retired(state: &Path, incoming: &Path) -> Result<()> {
    if fs::symlink_metadata(incoming)?.uid() != unsafe { libc::geteuid() } {
        return Ok(());
    }
    let state = parent_directory(state)?;
    let incoming = private_directory(incoming)?;
    for entry in fs::read_dir(crate::host::fd_path(incoming.as_raw_fd()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some((name, (vm_id, transfer_id))) = name.to_str().and_then(|name| name.split_once('-').map(|ids| (name, ids))) else { continue };
        if [vm_id, transfer_id].into_iter().any(|id| id.len() != 32 || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
            continue;
        }
        let Some(_bundle) = crate::host::try_lock_at(crate::host::host_locks()?, &bundle_key(&incoming, name)?)? else { continue };
        let _transfer = parent_lock(&state, libc::LOCK_EX)?;
        let path = entry.path();
        let Ok(directory) = private_directory(&path) else { continue };
        if crate::host::flock(&directory, libc::LOCK_EX | libc::LOCK_NB).is_err() {
            continue;
        }
        let Ok(offer) = super::record::<Offer>(&directory, "OFFER") else { continue };
        if offer.validate().is_err() || bundle_name(&offer) != name || offer.destination_host != host_id_in(&state)? {
            continue;
        }
        let obsolete = read_incoming(&state, &offer)?
            .is_some_and(|journal| journal.offer.generation > offer.generation || journal.offer == offer && journal.status == Status::Aborted);
        if !activate::reclaimable(&state, &offer, obsolete)? {
            continue;
        }
        let pinned = directory.metadata()?;
        if !fs::symlink_metadata(&path).is_ok_and(|selected| selected.is_dir() && (selected.dev(), selected.ino()) == (pinned.dev(), pinned.ino())) {
            continue;
        }
        // Move the retired bundle to the existing crash-recoverable staging
        // namespace before removing members. The selected name cannot reappear
        // because receive checks the same destination journal under this lock.
        let parent = crate::host::fd_path(incoming.as_raw_fd());
        let _staging = parent_lock(&incoming, libc::LOCK_EX)?;
        let retired = parent.join(format!("{}{}", crate::software_state::STAGING_PREFIX, util::random_hex(16)?));
        if util::rename_noreplace(&path, &retired)? {
            incoming.sync_all()?;
            fs::remove_dir_all(retired)?;
            incoming.sync_all()?;
        }
    }
    Ok(())
}

pub(crate) fn import(state: &Path, offer: &Path, reader: &mut dyn Read, max_mib: Option<&str>) -> Result<serde_json::Value> {
    let max_mib: u64 = max_mib.unwrap_or("16384").parse()?;
    let limit = max_mib.checked_mul(1 << 20).filter(|bytes| *bytes > 0 && *bytes <= i64::MAX as u64).ok_or("invalid software bundle size limit")?;
    let offer = read_input(offer)?;
    let bytes = receive(state, &offer, reader, limit)?;
    Ok(serde_json::json!({"status": "received", "bytes": bytes}))
}

#[cfg(test)]
mod tests {
    use super::super::{transition, Action};
    use super::*;
    use crate::test_util::TempDir;
    use base64::{engine::general_purpose::STANDARD, Engine};

    pub(super) fn wire(source: &Path, target: &Path) -> (Offer, Vec<u8>) {
        let (path, _) = crate::software_state::tests::checkpoint(source);
        let checkpoint = private_directory(&path).unwrap();
        let manifest = read_manifest(&checkpoint).unwrap();
        let offer = Offer {
            vm_id: manifest.vm_id.clone(),
            source_host: manifest.host_id.clone(),
            destination_host: super::super::host_id(target).unwrap(),
            transfer_id: "33".repeat(16),
            manifest_sha256: Retirement::of(&manifest).unwrap().manifest_sha256,
            generation: manifest.owner_generation + 1,
        };
        let header = Header { offer: offer.clone(), manifest };
        let mut wire = Vec::new();
        header.write(&mut wire).unwrap();
        for (name, _) in header.members() {
            member(&checkpoint, &name).unwrap().read_to_end(&mut wire).unwrap();
        }
        (offer, wire)
    }

    #[test]
    fn collection_keeps_pending_or_pinned_imports_and_reclaims_aborted_or_superseded_ones() {
        for supersede in [false, true] {
            let source = TempDir::new("transfer-collect-source");
            let target = TempDir::new("transfer-collect-target");
            let (offer, bytes) = wire(&source, &target);
            let key = STANDARD.encode([2; 32]);
            transition(&target, offer.clone(), Action::Prepare(key.clone(), Vec::new())).unwrap();
            receive(&target, &offer, &mut bytes.as_slice(), 1 << 20).unwrap();
            let path = target.join(INCOMING).join(bundle_name(&offer));
            crate::software_state::sweep(&target).unwrap();
            assert!(path.exists());

            let pinned = private_directory(&path).unwrap();
            crate::host::flock(&pinned, libc::LOCK_SH).unwrap();
            transition(&target, offer.clone(), Action::Abort).unwrap();
            if supersede {
                let next = Offer { transfer_id: "55".repeat(16), generation: offer.generation + 1, ..offer.clone() };
                transition(&target, next, Action::Prepare(key, Vec::new())).unwrap();
            }
            crate::software_state::sweep(&target).unwrap();
            assert!(path.exists());

            drop(pinned);
            crate::software_state::sweep(&target).unwrap();
            assert!(!path.exists());
            assert!(receive(&target, &offer, &mut bytes.as_slice(), 1 << 20).is_err());
            let state = parent_directory(&target).unwrap();
            assert!(read_incoming(&state, &offer).unwrap().is_some());
        }
    }

    #[test]
    fn verifies_bounded_input_before_publishing_and_reuses_only_a_verified_bundle() {
        let source = TempDir::new("transfer-bundle-source");
        let target = TempDir::new("transfer-bundle-target");
        let (offer, bytes) = wire(&source, &target);
        let limit = 1 << 20;
        assert!(receive(&target, &offer, &mut bytes.as_slice(), limit).is_err());
        transition(&target, offer.clone(), Action::Prepare(STANDARD.encode([2; 32]), Vec::new())).unwrap();
        let unrelated = TempDir::new("transfer-bundle-unrelated");
        assert!(receive(&unrelated, &offer, &mut bytes.as_slice(), limit).is_err());
        let incoming = target.join(INCOMING);
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let mut trailing = bytes.clone();
        trailing.push(0);
        for bad in [&corrupt[..], &trailing[..], &bytes[..bytes.len() - 1]] {
            let mut stream = bad;
            assert!(receive(&target, &offer, &mut stream, limit).is_err());
            assert_eq!(std::fs::read_dir(&incoming).unwrap().count(), 0);
        }
        assert!(receive(&target, &offer, &mut bytes.as_slice(), 1).is_err());
        let accepted = receive(&target, &offer, &mut bytes.as_slice(), limit).unwrap();
        assert_eq!(receive(&target, &offer, &mut bytes.as_slice(), limit).unwrap(), accepted);
        let published = private_directory(&incoming.join(format!("{}-{}", offer.vm_id, offer.transfer_id))).unwrap();
        assert_eq!(read_manifest(&published).unwrap().host_id, offer.source_host);
        for record in ["RETIRED", "STARTED", "DISCARDED", "HIGHEST"] {
            assert!(!present(&published, record).unwrap());
        }
        transition(&target, offer.clone(), Action::Abort).unwrap();
        assert!(receive(&target, &offer, &mut bytes.as_slice(), limit).unwrap_err().to_string().contains("aborted"));
    }

    #[test]
    fn abort_that_wins_during_streaming_prevents_publication() {
        let source = TempDir::new("transfer-bundle-race-source");
        let target = TempDir::new("transfer-bundle-race-target");
        let (offer, bytes) = wire(&source, &target);
        transition(&target, offer.clone(), Action::Prepare(STANDARD.encode([2; 32]), Vec::new())).unwrap();

        struct AbortAtEnd<'a> {
            bytes: &'a [u8],
            target: &'a Path,
            offer: &'a Offer,
        }
        impl Read for AbortAtEnd<'_> {
            fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
                if self.bytes.is_empty() {
                    transition(self.target, self.offer.clone(), Action::Abort).unwrap();
                }
                self.bytes.read(into)
            }
        }

        let mut stream = AbortAtEnd { bytes: &bytes, target: &target, offer: &offer };
        assert!(receive(&target, &offer, &mut stream, 1 << 20).unwrap_err().to_string().contains("aborted"));
        assert_eq!(std::fs::read_dir(target.join(INCOMING)).unwrap().count(), 0);
    }
}
