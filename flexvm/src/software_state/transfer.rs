//! Destination authority journal for software checkpoints. A transfer may be
//! committed only with a receipt from its configured source key.
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{host_id, host_id_in, parent_directory, parent_lock, present, record, write_record};
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
    fn validate(&self, local_host: &str) -> Result<()> {
        let hex = |s: &str, len| s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if [&self.vm_id, &self.source_host, &self.destination_host, &self.transfer_id].into_iter().any(|s| !hex(s, 32))
            || !hex(&self.manifest_sha256, 64)
            || self.generation == 0
        {
            bail!("invalid software transfer identity or generation");
        }
        if self.destination_host != local_host || self.source_host == local_host {
            bail!("software transfer does not name this host as its remote destination");
        }
        Ok(())
    }

    fn signing_message(&self) -> Result<Vec<u8>> {
        let mut message = RECEIPT_DOMAIN.to_vec();
        serde_json::to_writer(&mut message, self)?;
        Ok(message)
    }
}

#[derive(Deserialize)]
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
    offer.validate(&local_host)?;
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
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

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
    use ring::signature::{Ed25519KeyPair, KeyPair};

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
}
