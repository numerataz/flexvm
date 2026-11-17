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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    offer: Offer,
    destination_key: String,
    commit_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor: Option<Offer>,
}

impl Handoff {
    fn signing_message(&self) -> Result<Vec<u8>> {
        let mut message = HANDOFF_DOMAIN.to_vec();
        serde_json::to_writer(&mut message, self)?;
        Ok(message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Finalized {
    handoff: Handoff,
    signature: String,
}

impl Finalized {
    pub(super) fn verify_successor(&self, previous: &Offer, source_key: &str) -> Result<(&Offer, &str)> {
        let handoff = &self.handoff;
        let offer = &handoff.offer;
        offer.validate()?;
        if handoff.predecessor.as_ref() != Some(previous)
            || offer.vm_id != previous.vm_id
            || offer.source_host != previous.destination_host
            || offer.generation <= previous.generation
        {
            bail!("software handoff chain link does not continue its predecessor");
        }
        let source = decode::<32>(source_key, "source public key")?;
        let successor = decode::<32>(&handoff.destination_key, "destination public key")?;
        let proof = decode::<64>(&self.signature, "finalized handoff signature")?;
        UnparsedPublicKey::new(&ED25519, source).verify(&handoff.signing_message()?, &proof).map_err(|_| "invalid software finalized handoff signature")?;
        verify_commit_signature(offer, successor, &handoff.commit_signature)?;
        Ok((offer, &handoff.destination_key))
    }
}

fn verify_commit_signature(offer: &Offer, destination_key: [u8; 32], signature: &str) -> Result<()> {
    let signature = decode::<64>(signature, "commit signature")?;
    UnparsedPublicKey::new(&ED25519, destination_key)
        .verify(&offer.signing_message(COMMIT_DOMAIN)?, &signature)
        .map_err(|_| "invalid software transfer commit signature".into())
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
    verify_commit_signature(&receipt.offer, destination_key, &receipt.signature)?;
    if fence.finalized {
        state.sync_all()?;
    } else {
        fence.finalized = true;
        write_record(state, &source_record(&fence.offer.vm_id), &serde_json::to_vec(&fence)?, true)?;
    }
    let handoff = Handoff { offer: receipt.offer, destination_key: fence.destination_key, commit_signature: receipt.signature, predecessor: fence.predecessor };
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
            predecessor: None,
        };
        let path = source_record(&offer.vm_id);
        let mut legacy = serde_json::to_value(&fence).unwrap();
        legacy.as_object_mut().unwrap().remove("finalized");
        write_record(&source_dir, &path, &serde_json::to_vec(&legacy).unwrap(), false).unwrap();
        transition(&destination, offer.clone(), Action::Prepare(fence.source_key.clone(), Vec::new())).unwrap();
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

    #[test]
    fn intermediary_handoffs_need_exact_predecessors_and_closing_source_key() {
        let original = TempDir::new("handoff-origin");
        let state = parent_directory(&original).unwrap();
        let origin = host_id_in(&state).unwrap();
        let intermediary = Ed25519KeyPair::from_seed_unchecked(&[20; 32]).unwrap();
        let next = Ed25519KeyPair::from_seed_unchecked(&[21; 32]).unwrap();
        let last = Ed25519KeyPair::from_seed_unchecked(&[22; 32]).unwrap();
        let anchor = Offer {
            vm_id: "11".repeat(16),
            source_host: origin.clone(),
            destination_host: "22".repeat(16),
            transfer_id: "33".repeat(16),
            manifest_sha256: "44".repeat(32),
            generation: 5,
        };
        let fence = SourceFence {
            offer: anchor.clone(),
            source_key: STANDARD.encode([0; 32]),
            destination_key: STANDARD.encode(intermediary.public_key()),
            recovered: false,
            finalized: false,
            predecessor: None,
        };
        write_record(&state, &source_record(&anchor.vm_id), &serde_json::to_vec(&fence).unwrap(), false).unwrap();

        let create_link = |previous: &Offer, receiver: &str, id: &str, sender: &Ed25519KeyPair, receiver_key: &Ed25519KeyPair| {
            let offer = Offer {
                source_host: previous.destination_host.clone(),
                destination_host: receiver.repeat(16),
                transfer_id: id.repeat(16),
                generation: previous.generation + 1,
                ..previous.clone()
            };
            let commit_signature = signed_receipt(offer.clone(), receiver_key, COMMIT_DOMAIN).unwrap().signature;
            let handoff = Handoff { offer, destination_key: STANDARD.encode(receiver_key.public_key()), commit_signature, predecessor: Some(previous.clone()) };
            let signature = STANDARD.encode(sender.sign(&handoff.signing_message().unwrap()));
            Finalized { handoff, signature }
        };
        let first = create_link(&anchor, "55", "66", &intermediary, &next);
        let second = create_link(&first.handoff.offer, "77", "88", &next, &last);
        let returning = Offer {
            source_host: second.handoff.offer.destination_host.clone(),
            destination_host: origin,
            transfer_id: "99".repeat(16),
            generation: second.handoff.offer.generation + 1,
            ..anchor.clone()
        };
        let prepare = |key: &Ed25519KeyPair, chain| transition(&original, returning.clone(), Action::Prepare(STANDARD.encode(key.public_key()), chain));
        assert!(prepare(&last, Vec::new()).is_err());
        assert!(prepare(&last, vec![second.clone()]).is_err());
        assert!(prepare(&last, vec![second.clone(), first.clone()]).is_err());
        assert!(prepare(&next, vec![first.clone(), second.clone()]).is_err());
        let other_branch = create_link(&anchor, "55", "aa", &intermediary, &next);
        assert!(prepare(&last, vec![other_branch, second.clone()]).is_err());

        let mut substituted = second.clone();
        substituted.handoff.destination_key = STANDARD.encode(intermediary.public_key());
        assert!(prepare(&intermediary, vec![first.clone(), substituted]).is_err());

        let mut unsigned_commit = second.clone();
        unsigned_commit.handoff.commit_signature = STANDARD.encode([0; 64]);
        unsigned_commit.signature = STANDARD.encode(next.sign(&unsigned_commit.handoff.signing_message().unwrap()));
        assert!(prepare(&last, vec![first.clone(), unsigned_commit]).is_err());

        assert_eq!(prepare(&last, vec![first, second]).unwrap(), Status::Pending);
        let sig = signed_receipt(returning.clone(), &last, RECEIPT_DOMAIN).unwrap().signature;
        assert_eq!(transition(&original, returning.clone(), Action::Commit(sig)).unwrap(), Status::Committed);
        assert_eq!(super::super::committed_return_fence(&state, &returning).unwrap(), Some(anchor));
    }
}
