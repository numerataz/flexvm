//! Source and destination ownership journals for software checkpoint transfers.
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{host_id, host_id_in, parent_directory, parent_lock, present, private_directory, read_manifest, record, write_record, Manifest, Retirement};
use crate::host::{Host, PidFd};
use crate::{bail, util::Result};

const RECEIPT_DOMAIN: &[u8] = b"flexvm/software-retirement/v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    vm_id: String,
    source_host: String,
    destination_host: String,
    transfer_id: String,
    manifest_sha256: String,
    generation: u64,
}

impl Offer {
    fn validate(&self) -> Result<()> {
        let hex = |s: &str, len| s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if [&self.vm_id, &self.source_host, &self.destination_host, &self.transfer_id].into_iter().any(|s| !hex(s, 32))
            || !hex(&self.manifest_sha256, 64)
            || self.generation == 0
        {
            bail!("invalid software transfer identity or generation");
        }
        if self.destination_host == self.source_host {
            bail!("software transfer source and destination must differ");
        }
        Ok(())
    }

    fn signing_message(&self) -> Result<Vec<u8>> {
        let mut message = RECEIPT_DOMAIN.to_vec();
        serde_json::to_writer(&mut message, self)?;
        Ok(message)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    offer: Offer,
    signature: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pending,
    Committed,
    Aborted,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    offer: Offer,
    source_key: String,
    status: Status,
}

enum Action {
    Prepare(String),
    Commit(String),
    Abort,
}

fn transition(state: &Path, offer: Offer, action: Action) -> Result<Status> {
    let dir = parent_directory(state)?;
    let local_host = host_id_in(&dir)?;
    offer.validate()?;
    if offer.destination_host != local_host {
        bail!("software transfer does not name this host as its remote destination");
    }
    let _lock = parent_lock(&dir, libc::LOCK_EX)?;
    // A single durable record per VM retains its highest observed generation.
    let name = format!(".software-transfer-v1-{}", offer.vm_id);
    let previous: Option<Journal> = if present(&dir, &name)? { Some(record(&dir, &name)?) } else { None };
    let next = match action {
        Action::Prepare(source_key) => {
            decode::<32>(&source_key, "source public key")?;
            if let Some(current) = &previous {
                if current.offer == offer && current.source_key == source_key {
                    dir.sync_all()?;
                    return Ok(current.status);
                }
                if current.status != Status::Aborted || offer.generation <= current.offer.generation || offer.transfer_id == current.offer.transfer_id {
                    bail!("software transfer conflicts with the destination journal");
                }
            }
            Journal { offer, source_key, status: Status::Pending }
        }
        Action::Commit(signature) => {
            let mut current = matching(&previous, &offer)?;
            if current.status == Status::Aborted {
                bail!("software transfer was aborted");
            }
            let key = decode::<32>(&current.source_key, "source public key")?;
            let signature = decode::<64>(&signature, "retirement signature")?;
            UnparsedPublicKey::new(&ED25519, key).verify(&current.offer.signing_message()?, &signature).map_err(|_| "invalid software retirement signature")?;
            current.status = Status::Committed;
            current
        }
        Action::Abort => {
            let mut current = matching(&previous, &offer)?;
            if current.status == Status::Committed {
                bail!("committed software transfer cannot be aborted");
            }
            current.status = Status::Aborted;
            current
        }
    };
    if previous.as_ref() == Some(&next) {
        dir.sync_all()?;
    } else {
        write_record(&dir, &name, &serde_json::to_vec(&next)?, previous.is_some())?;
    }
    Ok(next.status)
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceFence {
    offer: Offer,
    source_key: String,
}

fn source_record(vm_id: &str) -> String {
    format!(".software-transfer-source-v1-{vm_id}")
}

/// Call under the state parent's exclusive lock, also taken by local grants.
pub(super) fn check_local_restart(state: &File, vm_id: &str) -> Result<()> {
    if present(state, &source_record(&vm_id.to_ascii_lowercase()))? {
        bail!("software VM retired for transfer; its source cannot restart it");
    }
    Ok(())
}

fn retired_checkpoint(checkpoint: &File) -> Result<(Manifest, Retirement)> {
    let manifest = read_manifest(checkpoint)?;
    let retirement = Retirement::of(&manifest)?;
    if present(checkpoint, "STARTED")? || present(checkpoint, "DISCARDED")? {
        bail!("software transfer needs an unconsumed checkpoint");
    }
    if !present(checkpoint, "RETIRED")? || record::<Retirement>(checkpoint, "RETIRED")? != retirement {
        bail!("software transfer needs an exact retirement record");
    }
    if PidFd::open(&manifest.source_owner)?.is_some() || PidFd::open(&manifest.source_engine)?.is_some() {
        bail!("software transfer source owner or engine is still alive");
    }
    Ok((manifest, retirement))
}

fn proposed_generation(checkpoint: &File, generation: u64) -> Result<u64> {
    let highest = if present(checkpoint, "HIGHEST")? { record::<u64>(checkpoint, "HIGHEST")? } else { generation };
    highest.max(generation).checked_add(1).ok_or_else(|| "software transfer generation exhausted".into())
}

pub(crate) fn offer(host: &Host, vm: &str, destination: &str) -> Result<serde_json::Value> {
    let _name = host.take_name(vm, true)?;
    let state = parent_directory(&host.state)?;
    let _transfer = parent_lock(&state, libc::LOCK_EX)?;
    let checkpoint = private_directory(&host.suspended(vm)?)?;
    let (manifest, retirement) = retired_checkpoint(&checkpoint)?;
    let local_host = host_id_in(&state)?;
    if manifest.host_id != local_host {
        bail!("software checkpoint does not belong to this source host");
    }
    check_local_restart(&state, &manifest.vm_id)?;
    let offer = Offer {
        vm_id: manifest.vm_id,
        source_host: local_host,
        destination_host: destination.into(),
        transfer_id: crate::util::random_hex(16)?,
        manifest_sha256: retirement.manifest_sha256,
        generation: proposed_generation(&checkpoint, manifest.owner_generation)?,
    };
    offer.validate()?;
    Ok(serde_json::to_value(offer)?)
}

fn issue(state: &File, checkpoint: &File, offer: Offer, key: &Ed25519KeyPair) -> Result<Receipt> {
    offer.validate()?;
    let local_host = host_id_in(state)?;
    let _transfer = parent_lock(state, libc::LOCK_EX)?;
    let (manifest, retirement) = retired_checkpoint(checkpoint)?;
    if offer.source_host != local_host
        || offer.source_host != manifest.host_id
        || offer.vm_id != manifest.vm_id
        || offer.manifest_sha256 != retirement.manifest_sha256
        || offer.generation < proposed_generation(checkpoint, manifest.owner_generation)?
    {
        bail!("transfer offer does not match the retired software checkpoint");
    }
    let path = source_record(&offer.vm_id);
    let fence = SourceFence { offer, source_key: STANDARD.encode(key.public_key()) };
    if present(state, &path)? {
        if record::<SourceFence>(state, &path)? != fence {
            bail!("software VM is already fenced for a different transfer or signing key");
        }
        // Retry a fence whose rename completed before its parent fsync did.
        state.sync_all()?;
    } else {
        write_record(state, &path, &serde_json::to_vec(&fence)?, false)?;
    }
    let signature = STANDARD.encode(key.sign(&fence.offer.signing_message()?));
    Ok(Receipt { offer: fence.offer, signature })
}

pub(crate) fn retire(host: &Host, vm: &str, input: &Path, signing_key: &Path) -> Result<serde_json::Value> {
    let offer = read_input(input)?;
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(signing_key)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        bail!("software transfer signing key must be a private regular file owned by this user");
    }
    let mut encoded = zeroize::Zeroizing::new(Vec::with_capacity(1025));
    file.take(1025).read_to_end(&mut encoded)?;
    if encoded.len() > 1024 {
        bail!("software transfer signing key is too large");
    }
    let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&encoded).map_err(|_| "invalid Ed25519 PKCS#8 DER signing key")?;
    let _name = host.take_name(vm, true)?;
    let state = parent_directory(&host.state)?;
    let checkpoint = private_directory(&host.suspended(vm)?)?;
    Ok(serde_json::to_value(issue(&state, &checkpoint, offer, &key)?)?)
}

fn matching(previous: &Option<Journal>, offer: &Offer) -> Result<Journal> {
    let Some(current) = previous.as_ref().filter(|j| &j.offer == offer) else {
        bail!("software transfer does not match a prepared destination");
    };
    Ok(Journal { offer: offer.clone(), source_key: current.source_key.clone(), status: current.status })
}

fn decode<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    STANDARD.decode(value)?.try_into().map_err(|_| format!("invalid software transfer {label} length").into())
}

fn read_input<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    if !file.metadata()?.is_file() {
        bail!("software transfer input must be a regular file");
    }
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        bail!("software transfer input exceeds 8 KiB");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn command(state: &Path, operation: &str, input: &Path, source_key: Option<&str>) -> Result<serde_json::Value> {
    let (offer, action) = match operation {
        "id" => return Ok(serde_json::json!({"host_id": host_id(state)?})),
        "prepare" => (read_input(input)?, Action::Prepare(source_key.ok_or("missing source key")?.into())),
        "commit" => {
            let Receipt { offer, signature } = read_input(input)?;
            (offer, Action::Commit(signature))
        }
        "abort" => (read_input(input)?, Action::Abort),
        _ => bail!("unsupported software transfer operation"),
    };
    let status = transition(state, offer, action)?;
    Ok(serde_json::json!({"status": status}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn offer(state: &Path) -> Offer {
        Offer {
            vm_id: "11".repeat(16),
            source_host: "22".repeat(16),
            destination_host: host_id(state).unwrap(),
            transfer_id: "33".repeat(16),
            manifest_sha256: "44".repeat(32),
            generation: 7,
        }
    }

    fn key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn public_key(key: &Ed25519KeyPair) -> Action {
        Action::Prepare(STANDARD.encode(key.public_key()))
    }

    fn sign(key: &Ed25519KeyPair, offer: &Offer) -> Action {
        Action::Commit(STANDARD.encode(key.sign(&offer.signing_message().unwrap())))
    }

    #[test]
    fn only_the_prepared_key_and_exact_offer_can_commit_and_retry() {
        let state = TempDir::new("transfer-commit");
        let offer = offer(&state);
        let signer = key(1);
        assert!(transition(&state, offer.clone(), sign(&signer, &offer)).is_err());
        assert_eq!(transition(&state, offer.clone(), public_key(&signer)).unwrap(), Status::Pending);
        assert!(transition(&state, offer.clone(), public_key(&key(2))).is_err());
        assert!(transition(&state, offer.clone(), sign(&key(2), &offer)).is_err());

        let altered = [
            Offer { vm_id: "55".repeat(16), ..offer.clone() },
            Offer { source_host: "55".repeat(16), ..offer.clone() },
            Offer { destination_host: "55".repeat(16), ..offer.clone() },
            Offer { transfer_id: "55".repeat(16), ..offer.clone() },
            Offer { manifest_sha256: "55".repeat(32), ..offer.clone() },
            Offer { generation: 8, ..offer.clone() },
        ];
        for other in altered {
            assert!(transition(&state, offer.clone(), sign(&signer, &other)).is_err(), "{other:?}");
        }
        for _ in 0..2 {
            assert_eq!(transition(&state, offer.clone(), sign(&signer, &offer)).unwrap(), Status::Committed);
        }
        assert!(transition(&state, offer.clone(), Action::Abort).is_err());
        assert_eq!(transition(&state, offer, public_key(&signer)).unwrap(), Status::Committed);
    }

    #[test]
    fn abort_permanently_rejects_old_receipts_and_advances_only_to_a_new_generation() {
        let state = TempDir::new("transfer-abort");
        let old = offer(&state);
        let signer = key(1);
        assert_eq!(transition(&state, old.clone(), public_key(&signer)).unwrap(), Status::Pending);
        for _ in 0..2 {
            assert_eq!(transition(&state, old.clone(), Action::Abort).unwrap(), Status::Aborted);
            assert!(transition(&state, old.clone(), sign(&signer, &old)).is_err());
        }
        assert_eq!(transition(&state, old.clone(), public_key(&signer)).unwrap(), Status::Aborted);
        let next = Offer { transfer_id: "55".repeat(16), ..old.clone() };
        assert!(transition(&state, next.clone(), public_key(&signer)).is_err());
        let next = Offer { generation: 8, ..next };
        assert_eq!(transition(&state, next.clone(), public_key(&signer)).unwrap(), Status::Pending);
        assert!(transition(&state, old.clone(), sign(&signer, &old)).is_err());
        assert!(transition(&state, old, public_key(&signer)).is_err());
        assert_eq!(transition(&state, next.clone(), sign(&signer, &next)).unwrap(), Status::Committed);
    }

    #[test]
    fn a_parallel_abort_and_commit_can_never_both_win() {
        let state = TempDir::new("transfer-race");
        let offer = offer(&state);
        let signer = key(1);
        transition(&state, offer.clone(), public_key(&signer)).unwrap();
        let receipt = sign(&signer, &offer);
        let barrier = std::sync::Barrier::new(2);
        let (committed, aborted) = std::thread::scope(|scope| {
            let commit = scope.spawn(|| {
                barrier.wait();
                transition(&state, offer.clone(), receipt)
            });
            barrier.wait();
            let abort = transition(&state, offer.clone(), Action::Abort);
            (commit.join().unwrap(), abort)
        });
        assert_ne!(committed.is_ok(), aborted.is_ok());
        let expected = if committed.is_ok() { Status::Committed } else { Status::Aborted };
        assert_eq!(transition(&state, offer, public_key(&signer)).unwrap(), expected);
    }

    #[test]
    fn a_destination_cannot_reuse_an_offer_addressed_to_another_host() {
        let first = TempDir::new("transfer-first");
        let another = TempDir::new("transfer-other");
        let offer = offer(&first);
        assert!(transition(&another, offer, public_key(&key(1))).unwrap_err().to_string().contains("destination"));
    }

    fn rewrite_manifest(checkpoint: &File, manifest: &Manifest) {
        for (name, bytes) in [
            ("manifest.json", serde_json::to_vec(manifest).unwrap()),
            ("OWNER", serde_json::to_vec(&manifest.source_owner).unwrap()),
            ("RETIRED", serde_json::to_vec(&Retirement::of(manifest).unwrap()).unwrap()),
        ] {
            write_record(checkpoint, name, &bytes, true).unwrap();
        }
    }

    #[test]
    fn issuance_fences_a_pending_local_grant_before_signing_and_survives_record_retry() {
        let root = TempDir::new("transfer-source");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let target = TempDir::new("transfer-receiver");
        let (path, profile) = super::super::tests::checkpoint(&root);
        let checkpoint = private_directory(&path).unwrap();
        let mut manifest = read_manifest(&checkpoint).unwrap();
        manifest.host_id = host_id(&host.state).unwrap();
        rewrite_manifest(&checkpoint, &manifest);

        let local = parent_directory(&host.state).unwrap();
        let mut outgoing = Offer {
            source_host: manifest.host_id.clone(),
            vm_id: manifest.vm_id.clone(),
            manifest_sha256: Retirement::of(&manifest).unwrap().manifest_sha256,
            generation: manifest.owner_generation + 1,
            ..offer(&target)
        };
        let signer = key(1);
        assert!(issue(&local, &checkpoint, outgoing.clone(), &signer).unwrap_err().to_string().contains("still alive"));
        assert!(!present(&local, &source_record(&outgoing.vm_id)).unwrap());

        manifest.source_owner = manifest.source_engine.clone();
        rewrite_manifest(&checkpoint, &manifest);
        outgoing.manifest_sha256 = Retirement::of(&manifest).unwrap().manifest_sha256;
        let name = host.take_name("vm", true).unwrap();
        let verified = super::super::open(&path, &profile).unwrap();
        let prepared = verified.prepare(&name, &manifest.host_id).unwrap();
        assert!(issue(&local, &checkpoint, outgoing.clone(), &signer).is_err(), "a superseded generation cannot be issued");

        outgoing.generation = prepared.generation + 1;
        transition(&target, outgoing.clone(), public_key(&signer)).unwrap();
        let first = issue(&local, &checkpoint, outgoing.clone(), &signer).unwrap();
        let replay = issue(&parent_directory(&host.state).unwrap(), &checkpoint, outgoing.clone(), &signer).unwrap();
        assert_eq!(first.signature, replay.signature);
        assert!(issue(&local, &checkpoint, outgoing.clone(), &key(2)).is_err());
        assert!(issue(&local, &checkpoint, Offer { transfer_id: "66".repeat(16), ..outgoing.clone() }, &signer).is_err());
        assert!(prepared.grant(crate::host::Ident::me()).err().unwrap().to_string().contains("cannot restart"));
        assert!(verified.prepare(&name, &manifest.host_id).err().unwrap().to_string().contains("cannot restart"));
        assert_eq!(transition(&target, first.offer, Action::Commit(first.signature)).unwrap(), Status::Committed);
    }
}
