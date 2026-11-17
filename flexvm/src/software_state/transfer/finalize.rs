//! A source can certify the key it handed ownership to after a durable commit.
use std::fs::File;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use super::{
    decode, host_id_in, incoming_journal, parent_directory, parent_lock, read_fence, read_input, signed_receipt, signing_key, source_record, write_record,
    Offer, Receipt, Status,
};
use crate::{bail, util::Result};

const COMMIT_DOMAIN: &[u8] = b"flexvm/software-destination-commit/v1\0";
const HANDOFF_DOMAIN: &[u8] = b"flexvm/software-finalized-handoff/v1\0";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    offer: Offer,
    destination_key: String,
    commit_signature: String,
}

impl Handoff {
    fn signing_message(&self) -> Result<Vec<u8>> {
        let mut message = HANDOFF_DOMAIN.to_vec();
        serde_json::to_writer(&mut message, self)?;
        Ok(message)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Finalized {
    handoff: Handoff,
    signature: String,
}

fn commit_ack(state: &File, offer: Offer, key: &Ed25519KeyPair) -> Result<Receipt> {
    let _transfer = parent_lock(state, libc::LOCK_EX)?;
    let journal = incoming_journal(state, &offer)?;
    if journal.status != Status::Committed {
        bail!("software transfer needs a committed destination before acknowledgment");
    }
    // A replay also reestablishes durability if the original commit had an
    // ambiguous directory sync result.
    state.sync_all()?;
    signed_receipt(offer, key, COMMIT_DOMAIN)
}

fn certify(state: &File, receipt: Receipt, key: &Ed25519KeyPair) -> Result<Finalized> {
    receipt.offer.validate()?;
    if receipt.offer.source_host != host_id_in(state)? {
        bail!("commit acknowledgment does not name this source host");
    }
    let _transfer = parent_lock(state, libc::LOCK_EX)?;
    let Some(mut fence) = read_fence(state, &receipt.offer.vm_id)?.filter(|record| record.offer == receipt.offer) else {
        bail!("commit acknowledgment does not match a source fence");
    };
    if fence.recovered {
        bail!("recovered software transfer cannot be finalized");
    }
    if STANDARD.encode(key.public_key()) != fence.source_key {
        bail!("software transfer finalization needs the pinned source signing key");
    }
    let destination_key = decode::<32>(&fence.destination_key, "destination public key")?;
    let signature = decode::<64>(&receipt.signature, "commit signature")?;
    UnparsedPublicKey::new(&ED25519, destination_key)
        .verify(&receipt.offer.signing_message(COMMIT_DOMAIN)?, &signature)
        .map_err(|_| "invalid software transfer commit signature")?;
    if fence.finalized {
        state.sync_all()?;
    } else {
        fence.finalized = true;
        write_record(state, &source_record(&fence.offer.vm_id), &serde_json::to_vec(&fence)?, true)?;
    }
    let handoff = Handoff { offer: receipt.offer, destination_key: fence.destination_key, commit_signature: receipt.signature };
    let signature = STANDARD.encode(key.sign(&handoff.signing_message()?));
    Ok(Finalized { handoff, signature })
}

pub(crate) fn acknowledge(state: &Path, input: &Path, key_file: &Path) -> Result<serde_json::Value> {
    let state = parent_directory(state)?;
    Ok(serde_json::to_value(commit_ack(&state, read_input(input)?, &signing_key(key_file)?)?)?)
}

pub(crate) fn outgoing(state: &Path, input: &Path, key_file: &Path) -> Result<serde_json::Value> {
    let state = parent_directory(state)?;
    Ok(serde_json::to_value(certify(&state, read_input(input)?, &signing_key(key_file)?)?)?)
}

#[cfg(test)]
mod tests {
    use super::super::{recover_source, transition, Action, SourceFence, ABORT_DOMAIN, RECEIPT_DOMAIN};
    use super::*;
    use crate::test_util::TempDir;

    #[test]
    fn finalized_handoff_requires_both_pinned_keys_and_excludes_source_recovery() {
        let source = TempDir::new("handoff-source");
        let destination = TempDir::new("handoff-destination");
        let source_dir = parent_directory(&source).unwrap();
        let destination_dir = parent_directory(&destination).unwrap();
        let source_key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
        let destination_key = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
        let mut offer = Offer {
            vm_id: "11".repeat(16),
            source_host: host_id_in(&source_dir).unwrap(),
            destination_host: host_id_in(&destination_dir).unwrap(),
            transfer_id: "22".repeat(16),
            manifest_sha256: "33".repeat(32),
            generation: 5,
        };
        let mut fence = SourceFence {
            offer: offer.clone(),
            source_key: STANDARD.encode(source_key.public_key()),
            destination_key: STANDARD.encode(destination_key.public_key()),
            recovered: false,
            finalized: false,
        };
        let path = source_record(&offer.vm_id);
        let mut legacy = serde_json::to_value(&fence).unwrap();
        legacy.as_object_mut().unwrap().remove("finalized");
        write_record(&source_dir, &path, &serde_json::to_vec(&legacy).unwrap(), false).unwrap();
        transition(&destination, offer.clone(), Action::Prepare(fence.source_key.clone())).unwrap();
        assert!(commit_ack(&destination_dir, offer.clone(), &destination_key).is_err());
        let signature = signed_receipt(offer.clone(), &source_key, RECEIPT_DOMAIN).unwrap().signature;
        transition(&destination, offer.clone(), Action::Commit(signature)).unwrap();

        let wrong_key = commit_ack(&destination_dir, offer.clone(), &source_key).unwrap();
        assert!(certify(&source_dir, wrong_key, &source_key).unwrap_err().to_string().contains("invalid software transfer commit signature"));
        let ack = || commit_ack(&destination_dir, offer.clone(), &destination_key).unwrap();
        assert!(certify(&source_dir, ack(), &destination_key).unwrap_err().to_string().contains("pinned source signing key"));
        assert!(certify(&source_dir, signed_receipt(offer.clone(), &destination_key, ABORT_DOMAIN).unwrap(), &source_key).is_err());

        let result = certify(&source_dir, ack(), &source_key).unwrap();
        assert_eq!(certify(&source_dir, ack(), &source_key).unwrap(), result);
        assert_eq!(result.handoff.destination_key, fence.destination_key);
        UnparsedPublicKey::new(&ED25519, source_key.public_key())
            .verify(&result.handoff.signing_message().unwrap(), &STANDARD.decode(&result.signature).unwrap())
            .unwrap();
        assert!(read_fence(&source_dir, &offer.vm_id).unwrap().unwrap().finalized);
        let abort = signed_receipt(offer.clone(), &destination_key, ABORT_DOMAIN).unwrap();
        assert!(recover_source(&source_dir, abort).unwrap_err().to_string().contains("finalized"));

        // A separate transfer that already recovered must also reject a late
        // commit acknowledgment, even when both receipts verify.
        offer.generation += 1;
        offer.transfer_id = "44".repeat(16);
        fence.offer = offer.clone();
        write_record(&source_dir, &path, &serde_json::to_vec(&fence).unwrap(), true).unwrap();
        recover_source(&source_dir, signed_receipt(offer.clone(), &destination_key, ABORT_DOMAIN).unwrap()).unwrap();
        let late_ack = signed_receipt(offer, &destination_key, COMMIT_DOMAIN).unwrap();
        assert!(certify(&source_dir, late_ack, &source_key).unwrap_err().to_string().contains("recovered"));
    }
}
