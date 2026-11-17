//! A destination grant survives the imported directory and the VM name.
//! A recovered or retried command cannot grant execution a second time.
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::{bundle_name, Header, INCOMING};
use crate::host::{Ident, NameLock, PidFd};
use crate::software_state::transfer::{committed_return_fence, read_fence, read_input, require_disk_source, Offer};
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
    #[serde(default)]
    finished: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disks: Vec<crate::software_state::Disk>,
}

pub(crate) struct Activation<'a> {
    state: File,
    directory: File,
    header: Header,
    decision: Decision,
    _name: &'a NameLock,
}

const DECISION_PREFIX: &str = ".software-activation-v1-";

fn decision_name(vm_id: &str) -> String {
    format!("{DECISION_PREFIX}{vm_id}")
}

/// Read only while holding source and destination authority for this state root.
pub(in crate::software_state::transfer) fn require_disk_not_reserved(state: &File, disk_id: &str, same_vm: Option<&str>) -> Result<()> {
    for entry in fs::read_dir(crate::host::fd_path(state.as_raw_fd()))? {
        let name = entry?.file_name();
        let Some((name, vm_id)) = name.to_str().and_then(|name| name.strip_prefix(DECISION_PREFIX).map(|id| (name, id))) else { continue };
        if !crate::volume::valid_id(vm_id) || Some(vm_id) == same_vm {
            continue;
        }
        let decision: Decision = record(state, name)?;
        if decision.grant.is_none() && decision.disks.iter().any(|disk| disk.volume_id == disk_id) {
            bail!("managed volume {disk_id} is reserved for a pending software activation");
        }
    }
    Ok(())
}

fn read_decision(state: &File, vm_id: &str) -> Result<Option<Decision>> {
    let key = decision_name(vm_id);
    if present(state, &key)? {
        Ok(Some(record(state, &key)?))
    } else {
        Ok(None)
    }
}

pub(in crate::software_state::transfer) fn preceding_grant(state: &File, manifest: &Manifest) -> Result<Option<Offer>> {
    let decision = read_decision(state, &manifest.vm_id.to_ascii_lowercase())?;
    Ok(decision.filter(|d| d.grant.as_ref().is_some_and(|grant| grant.generation <= manifest.owner_generation)).map(|d| d.offer))
}

fn decision_for_offer(state: &File, offer: &Offer) -> Result<Option<Decision>> {
    Ok(read_decision(state, &offer.vm_id)?.filter(|decision| decision.offer == *offer))
}

pub(in crate::software_state::transfer) fn routed_grant(state: &File, offer: &Offer) -> Result<(String, Grant)> {
    let decision = decision_for_offer(state, offer)?.filter(|decision| !decision.finished).ok_or("software route has no current activation")?;
    let grant = decision.grant.ok_or("software route has no execution grant")?;
    if PidFd::open(&grant.owner)?.is_none() || PidFd::open(&grant.engine)?.is_none() {
        bail!("software route destination owner or engine has exited");
    }
    Ok((decision.name, grant))
}

pub(in crate::software_state::transfer) fn finished(state: &File, offer: &Offer) -> Result<bool> {
    Ok(decision_for_offer(state, offer)?.is_some_and(|decision| decision.finished))
}

pub(super) fn reclaimable(state: &File, offer: &Offer, obsolete: bool) -> Result<bool> {
    let decision = decision_for_offer(state, offer)?;
    if !obsolete && !decision.as_ref().is_some_and(|d| d.finished) {
        return Ok(false);
    }
    match decision.and_then(|decision| decision.grant) {
        Some(grant) => Ok(PidFd::open(&grant.engine)?.is_none()),
        None => Ok(true),
    }
}

/// Use only under the host transfer lock. A new outbound fence always
/// supersedes an older inbound grant.
pub(in crate::software_state::transfer) fn return_grant_generation(state: &File, outgoing: &Offer) -> Result<Option<u64>> {
    let decision = read_decision(state, &outgoing.vm_id)?;
    Ok(decision.filter(|decision| decision.return_fence.as_ref() == Some(outgoing)).and_then(|decision| decision.grant).map(|grant| grant.generation))
}

fn returning_disks(state: &File, offer: &Offer, anchor: Option<&Offer>) -> Result<Vec<crate::software_state::Disk>> {
    Ok(read_fence(state, &offer.vm_id)?.filter(|fence| Some(&fence.offer) == anchor && !fence.recovered).map_or_else(Vec::new, |fence| fence.disks))
}

fn import_id(offer: &Offer) -> crate::volume::ImportId {
    crate::volume::ImportId { vm_id: offer.vm_id.clone(), transfer_id: offer.transfer_id.clone() }
}

pub(in crate::software_state) struct Import {
    state: File,
    offer: Offer,
}

impl Import {
    pub(in crate::software_state) fn finish(&self, grant: &Grant) -> Result<()> {
        if grant.owner != Ident::me() || PidFd::open(&grant.engine)?.is_some() {
            bail!("software import is still in use");
        }
        let _transfer = parent_lock(&self.state, libc::LOCK_EX)?;
        let Some(mut decision) = decision_for_offer(&self.state, &self.offer)? else {
            bail!("software import grant is no longer selected");
        };
        if decision.grant.as_ref() != Some(grant) {
            bail!("software import grant changed before retirement");
        }
        if decision.finished {
            self.state.sync_all()?;
        } else {
            decision.finished = true;
            write_record(&self.state, &decision_name(&self.offer.vm_id), &serde_json::to_vec(&decision)?, true)?;
        }
        Ok(())
    }
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
        let previous = read_decision(&state, &offer.vm_id)?;
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
        if !header.manifest.disks.is_empty() {
            let catalog = crate::volume::Catalog::from_state(state.try_clone()?)?;
            let returning = returning_disks(&state, &offer, return_fence.as_ref())?;
            let tag = import_id(&offer);
            for disk in &header.manifest.disks {
                require_disk_not_reserved(&state, &disk.volume_id, Some(&offer.vm_id))?;
                require_disk_source(&state, &disk.volume_id, return_fence.as_ref())?;
                catalog.check_adoption(&disk.volume_id, &tag, returning.iter().any(|old| old.volume_id == disk.volume_id))?;
            }
        }
        let generation = floor.checked_add(1).ok_or("software activation generation exhausted")?;
        let decision =
            Decision { offer, name: name.name.clone(), generation, grant: None, return_fence, finished: false, disks: header.manifest.disks.clone() };
        let bytes = serde_json::to_vec(&decision)?;
        if bytes.len() > 8192 {
            bail!("software disk activation decision is too large");
        }
        write_record(&state, &key, &bytes, previous.is_some())?;
        Ok(Self { state, directory, header, decision, _name: name })
    }

    pub(crate) fn manifest(&self) -> &Manifest {
        &self.header.manifest
    }

    pub(in crate::software_state::transfer) fn offer(&self) -> &Offer {
        &self.decision.offer
    }

    pub(crate) fn returns_routed_address(&self) -> bool {
        self.decision.return_fence.as_ref().is_some_and(|previous| previous.routed.is_some())
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

    pub(crate) fn adopt_disks(&self) -> Result<Vec<crate::volume::Writer>> {
        if self.decision.disks.is_empty() {
            return Ok(Vec::new());
        }
        let returning = {
            let _transfer = parent_lock(&self.state, libc::LOCK_EX)?;
            if committed_return_fence(&self.state, &self.decision.offer)? != self.decision.return_fence
                || record::<Decision>(&self.state, &decision_name(&self.decision.offer.vm_id))? != self.decision
            {
                bail!("software disk activation preparation was superseded");
            }
            returning_disks(&self.state, &self.decision.offer, self.decision.return_fence.as_ref())?
        };
        let tag = import_id(&self.decision.offer);
        let catalog = crate::volume::Catalog::from_state(self.state.try_clone()?)?;
        self.decision
            .disks
            .iter()
            .map(|disk| {
                let source = crate::software_state::member(&self.directory, &disk.filename())?;
                let may_replace = returning.iter().any(|previous| previous.volume_id == disk.volume_id);
                disk.verify_writer(catalog.adopt(&disk.volume_id, disk.content.bytes, &source, &tag, may_replace)?)
            })
            .collect()
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
        let bytes = serde_json::to_vec(&self.decision)?;
        if bytes.len() > 8192 {
            bail!("software disk activation grant is too large");
        }
        write_record(&self.state, &key, &bytes, true)?;
        let import = Import { state: self.state, offer: self.decision.offer };
        Ok((generation, Consumed { directory: self.directory, grant, manifest: self.header.manifest, replaced: Mutex::new(Vec::new()), import: Some(import) }))
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

    #[test]
    fn collection_preserves_ambiguous_activations_and_reclaims_clean_retirements() {
        for clean in [false, true] {
            let source = TempDir::new("bundle-retire-source");
            let target = TempDir::new("bundle-retire-target");
            let host = Host::open(&target.join("state"), &target.join("run")).unwrap();
            let (offer, bytes) = super::super::tests::wire(&source, &host.state);
            let key = Ed25519KeyPair::from_seed_unchecked(&[5; 32]).unwrap();
            transition(&host.state, offer.clone(), Action::Prepare(STANDARD.encode(key.public_key()), Vec::new())).unwrap();
            let sig = STANDARD.encode(key.sign(&offer.signing_message(RECEIPT_DOMAIN).unwrap()));
            transition(&host.state, offer.clone(), Action::Commit(sig)).unwrap();
            super::super::receive(&host.state, &offer, &mut bytes.as_slice(), 1 << 20).unwrap();
            let name = host.take_name("activated", false).unwrap();
            let activation = Activation::prepare_offer(&name, offer.clone()).unwrap();
            let mut engine = crate::test_util::ChildGuard(std::process::Command::new("sleep").arg("60").spawn().unwrap());
            let (_, consumed) = activation.grant(Ident::of(engine.id()).unwrap()).unwrap();
            let import = consumed.import.as_ref().unwrap();
            assert!(import.finish(&consumed.grant).unwrap_err().to_string().contains("still in use"));
            engine.kill().unwrap();
            engine.wait().unwrap();
            if clean {
                import.finish(&consumed.grant).unwrap();
                import.finish(&consumed.grant).unwrap();
            }
            drop(consumed);
            crate::software_state::sweep(&host.state).unwrap();
            let path = host.state.join(INCOMING).join(bundle_name(&offer));
            assert_eq!(path.exists(), !clean);
            assert!(Activation::prepare_offer(&name, offer.clone()).err().unwrap().to_string().contains("already granted"));
            assert_eq!(super::super::receive(&host.state, &offer, &mut bytes.as_slice(), 1 << 20).is_ok(), !clean);
        }
    }
}
