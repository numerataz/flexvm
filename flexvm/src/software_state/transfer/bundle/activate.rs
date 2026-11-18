//! A destination grant survives the imported directory and the VM name.
//! A recovered or retried command cannot grant execution a second time.
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::{bundle_name, Header, INCOMING};
use crate::host::{Ident, NameLock, PidFd};
use crate::software_state::transfer::{committed_return_fence, read_input, Offer};
use crate::software_state::{
    open_pinned, parent_directory, parent_lock, present, private_directory, read_manifest, record, write_record, Consumed, Grant, Input, Manifest, Profile,
    Verified,
};
use crate::{bail, util::Result};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    offer: Offer,
    name: String,
    generation: u64,
    grant: Option<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    return_fence: Option<Offer>,
}

pub(crate) struct Activation<'a> {
    state: File,
    directory: File,
    header: Header,
    decision: Decision,
    _name: &'a NameLock,
}

fn decision_name(vm_id: &str) -> String {
    format!(".software-activation-v1-{vm_id}")
}

pub(in crate::software_state::transfer) fn preceding_grant(state: &File, manifest: &Manifest) -> Result<Option<Offer>> {
    let key = decision_name(&manifest.vm_id.to_ascii_lowercase());
    if !present(state, &key)? {
        return Ok(None);
    }
    let decision = record::<Decision>(state, &key)?;
    Ok(decision.grant.filter(|grant| grant.generation <= manifest.owner_generation).map(|_| decision.offer))
}

/// Use only under the host transfer lock. A new outbound fence always
/// supersedes an older inbound grant.
pub(in crate::software_state::transfer) fn return_grant_generation(state: &File, outgoing: &Offer) -> Result<Option<u64>> {
    let key = decision_name(&outgoing.vm_id);
    if !present(state, &key)? {
        return Ok(None);
    }
    let decision = record::<Decision>(state, &key)?;
    Ok(decision.grant.filter(|_| decision.return_fence.as_ref() == Some(outgoing)).map(|grant| grant.generation))
}

impl<'a> Activation<'a> {
    pub(crate) fn prepare(name: &'a NameLock, input: &Path) -> Result<Self> {
        Self::prepare_offer(name, read_input(input)?)
    }

    fn prepare_offer(name: &'a NameLock, offer: Offer) -> Result<Self> {
        let state = parent_directory(name.state_path())?;
        let _transfer = parent_lock(&state, libc::LOCK_EX)?;
        let return_fence = committed_return_fence(&state, &offer)?;
        let key = decision_name(&offer.vm_id);
        let previous = if present(&state, &key)? { Some(record::<Decision>(&state, &key)?) } else { None };
        let mut floor = offer.generation;
        if let Some(previous) = &previous {
            if previous.offer == offer {
                if previous.grant.is_some() {
                    bail!("software transfer already granted execution; this activation cannot be replayed");
                }
                if previous.name != name.name || previous.return_fence != return_fence {
                    bail!("software activation is already bound to another offer or VM name");
                }
                floor = floor.max(previous.generation);
            } else if return_fence.as_ref().is_none_or(|fence| fence.generation <= previous.generation) {
                bail!("software activation cannot supersede the previous execution decision");
            }
        }
        let root = crate::host::fd_path(state.as_raw_fd()).join(INCOMING);
        let incoming = private_directory(&root)?;
        let directory = private_directory(&crate::host::fd_path(incoming.as_raw_fd()).join(bundle_name(&offer)))?;
        crate::host::flock(&directory, libc::LOCK_SH)?;
        if record::<Offer>(&directory, "OFFER")? != offer {
            bail!("imported software checkpoint does not match the activation offer");
        }
        let header = Header { offer: offer.clone(), manifest: read_manifest(&directory)? };
        header.check(&offer)?;
        let generation = floor.checked_add(1).ok_or("software activation generation exhausted")?;
        let decision = Decision { offer, name: name.name.clone(), generation, grant: None, return_fence };
        write_record(&state, &key, &serde_json::to_vec(&decision)?, previous.is_some())?;
        Ok(Self { state, directory, header, decision, _name: name })
    }

    pub(crate) fn manifest(&self) -> &Manifest {
        &self.header.manifest
    }

    pub(crate) fn verify_inputs(&self, profiles: &[Profile], trusted_engine: &Path) -> Result<Verified> {
        let local = Input::open(&trusted_engine.canonicalize()?)?;
        if local.artifact != self.header.manifest.engine {
            bail!("trusted local QEMU does not match the imported engine digest and size");
        }
        let mut verified = open_pinned(self.directory.try_clone()?, profiles)?;
        let header = Header { offer: self.header.offer.clone(), manifest: verified.manifest.clone() };
        header.check(&self.decision.offer)?;
        // The signed source has authority over the guest, but never over which
        // host binary the destination runs. Launch from this local descriptor.
        verified.inputs.engine = local;
        Ok(verified)
    }

    pub(crate) fn grant(mut self, engine: Ident) -> Result<(u64, Consumed)> {
        let _transfer = parent_lock(&self.state, libc::LOCK_EX)?;
        if committed_return_fence(&self.state, &self.decision.offer)? != self.decision.return_fence {
            bail!("software activation outgoing handoff changed before the grant");
        }
        let key = decision_name(&self.decision.offer.vm_id);
        if record::<Decision>(&self.state, &key)? != self.decision {
            bail!("software activation preparation was superseded");
        }
        if PidFd::open(&engine)?.is_none() {
            bail!("software activation engine exited before the grant");
        }
        let generation = self.decision.generation;
        let grant = Grant {
            manifest_sha256: self.decision.offer.manifest_sha256.clone(),
            snapshot_id: self.header.manifest.snapshot_id.clone(),
            generation,
            owner: Ident::me(),
            engine,
        };
        self.decision.grant = Some(grant.clone());
        write_record(&self.state, &key, &serde_json::to_vec(&self.decision)?, true)?;
        Ok((generation, Consumed { directory: self.directory, grant, manifest: self.header.manifest, replaced: Mutex::new(Vec::new()) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::Host;
    use crate::software_state::transfer::{transition, Action, RECEIPT_DOMAIN};
    use crate::test_util::TempDir;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn activation_is_granted_once_and_uses_a_verified_local_engine() {
        let source = TempDir::new("bundle-activate-source");
        let target = TempDir::new("bundle-activate-target");
        let host = Host::open(&target.join("state"), &target.join("run")).unwrap();
        let (offer, bytes) = super::super::tests::wire(&source, &host.state);
        let key = Ed25519KeyPair::from_seed_unchecked(&[5; 32]).unwrap();
        transition(&host.state, offer.clone(), Action::Prepare(STANDARD.encode(key.public_key()), Vec::new())).unwrap();
        let name = host.take_name("remote", false).unwrap();
        super::super::receive(&host.state, &offer, &mut bytes.as_slice(), 1 << 20).unwrap();
        assert!(Activation::prepare_offer(&name, offer.clone()).err().unwrap().to_string().contains("requires a committed"));

        let sig = STANDARD.encode(key.sign(&offer.signing_message(RECEIPT_DOMAIN).unwrap()));
        transition(&host.state, offer.clone(), Action::Commit(sig)).unwrap();
        let discarded = Activation::prepare_offer(&name, offer.clone()).unwrap();
        let profile = discarded.manifest().profile.clone();
        assert!(discarded.verify_inputs(std::slice::from_ref(&profile), &source.join("source-kernel")).err().unwrap().to_string().contains("does not match"));
        let different = host.take_name("different", false).unwrap();
        assert!(Activation::prepare_offer(&different, offer.clone()).err().unwrap().to_string().contains("another offer or VM name"));

        let current = Activation::prepare_offer(&name, offer.clone()).unwrap();
        assert!(discarded.grant(Ident::me()).err().unwrap().to_string().contains("superseded"));
        let verified = current.verify_inputs(&[profile], &source.join("source-engine")).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(verified.inputs.engine.file.metadata().unwrap().ino(), std::fs::metadata(source.join("source-engine")).unwrap().ino());
        let (generation, consumed) = current.grant(Ident::me()).unwrap();
        assert!(generation > offer.generation);
        drop(consumed);
        // The once-only grant survives the bundle itself and another requested name.
        std::fs::remove_dir_all(host.state.join(INCOMING).join(bundle_name(&offer))).unwrap();
        assert!(Activation::prepare_offer(&different, offer).err().unwrap().to_string().contains("already granted"));
    }
}
