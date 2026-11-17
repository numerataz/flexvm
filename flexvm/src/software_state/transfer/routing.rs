//! Bind a peer's installed route to the exact software execution grant.
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use super::{bundle::activate, decode, host_id_in, parent_directory, parent_lock, read_fence, read_input, signing_key, Offer};
use crate::host::{Backend, Hop, Host};
use crate::{bail, util::Result};

const ROUTE_DOMAIN: &[u8] = b"flexvm/software-routed-activation/v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    offer: Offer,
    via: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    via6: Option<Ipv6Addr>,
}

impl Delivery {
    fn signing_message(&self) -> Result<Vec<u8>> {
        let mut message = ROUTE_DOMAIN.to_vec();
        serde_json::to_writer(&mut message, self)?;
        Ok(message)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgement {
    delivery: Delivery,
    signature: String,
}

pub(crate) fn acknowledge(host: &Host, input: &Path, key: &Path) -> Result<serde_json::Value> {
    let offer = read_input(input)?;
    Ok(serde_json::to_value(sign_route(host, &offer, &signing_key(key)?)?)?)
}

fn sign_route(host: &Host, offer: &Offer, key: &Ed25519KeyPair) -> Result<Acknowledgement> {
    offer.validate()?;
    let network = offer.routed.ok_or("software route acknowledgement needs a routed offer")?;
    let revision = network.revision.and_then(|rev| rev.checked_add(1)).ok_or("software route revision is exhausted")?;
    let state = parent_directory(&host.state)?;
    if offer.destination_host != host_id_in(&state)? {
        bail!("software route offer does not name this destination");
    }
    let _transfer = parent_lock(&state, libc::LOCK_EX)?;
    let (name, grant) = activate::routed_grant(&state, offer)?;
    let lock = host.lock()?;
    let address = host.addr(&lock, network.address.v4)?;
    let entry = host.entry(&name)?;
    if address.holder_id.as_ref() != Some(&grant.owner)
        || address.holder.as_deref() != Some(&name)
        || address.seen != network.generation
        || address.rev != revision
        || address.withdrawn
        || address.lent.is_some()
        || entry.ident != grant.owner
        || entry.ip != Some(network.address.v4)
        || !matches!(&entry.backend, Backend::QemuTcg { process, .. } if process == &grant.engine)
        || !matches!(entry.state.as_str(), "running" | "paused")
    {
        bail!("software route has not been published by its current execution grant");
    }
    let config = host.config_now();
    let via = Hop::of(config.underlay_known(), config.underlay6_known()).ok_or("software route destination has no configured underlay")?;
    if network.address.v6.is_some() && via.via6().is_none() {
        bail!("software IPv6 route needs the destination's IPv6 underlay");
    }
    let delivery = Delivery { offer: offer.clone(), via: via.via(), via6: via.via6() };
    let signature = STANDARD.encode(key.sign(&delivery.signing_message()?));
    Ok(Acknowledgement { delivery, signature })
}

pub(crate) fn install(host: &Host, input: &Path) -> Result<serde_json::Value> {
    install_ack(host, read_input(input)?)
}

pub(crate) fn request(host: &Host, request: &serde_json::Value) -> Result<serde_json::Value> {
    install_ack(host, serde_json::from_value(request["acknowledgement"].clone())?)
}

fn install_ack(host: &Host, acknowledgement: Acknowledgement) -> Result<serde_json::Value> {
    let Acknowledgement { delivery, signature } = acknowledgement;
    let offer = &delivery.offer;
    offer.validate()?;
    let network = offer.routed.ok_or("software route receipt needs a routed offer")?;
    let revision = network.revision.and_then(|rev| rev.checked_add(1)).ok_or("software route revision is exhausted")?;
    let state = parent_directory(&host.state)?;
    if offer.source_host != host_id_in(&state)? {
        bail!("software route receipt does not name this source");
    }
    let _transfer = parent_lock(&state, libc::LOCK_EX)?;
    let fence = read_fence(&state, &offer.vm_id)?.filter(|record| &record.offer == offer).ok_or("software route does not match the source transfer fence")?;
    if !fence.active(&state)? {
        bail!("software route transfer has already returned or was aborted");
    }
    let proof = decode::<64>(&signature, "software route signature")?;
    let key = decode::<32>(&fence.destination_key, "destination public key")?;
    UnparsedPublicKey::new(&ED25519, key).verify(&delivery.signing_message()?, &proof).map_err(|_| "invalid software route acknowledgement")?;
    let via = Hop::new(delivery.via, delivery.via6)?;
    let peers = crate::listen::known_peers(host)?;
    for hop in via.addrs() {
        crate::listen::check_via(hop, &peers)?;
    }
    if host.config_now().vm_addr(network.address.v4) != network.address {
        bail!("software route no longer matches the source network");
    }
    let lock = host.lock()?;
    host.install_software_route(&lock, network.address.v4, network.generation, revision, via)?;
    Ok(serde_json::json!({"status":"routed","address":network.address,"generation":network.generation,"revision":revision,"via":via.via(),"via6":via.via6()}))
}

pub(crate) struct Automatic {
    offer: Offer,
    peer: String,
    key: Ed25519KeyPair,
}

impl Automatic {
    pub(crate) fn prepare(host: &Host, activation: &activate::Activation<'_>, peer: &str, key: &Path) -> Result<Self> {
        let offer = activation.offer();
        if offer.routed.is_none() {
            bail!("automatic software routing needs a routed transfer offer");
        }
        if !host.config_now().peers.iter().any(|configured| configured == peer) {
            bail!("software route source must be a configured peer");
        }
        Ok(Self { offer: offer.clone(), peer: peer.into(), key: signing_key(key)? })
    }

    pub(crate) fn deliver(&self, host: &Host) -> Result<()> {
        let send = || {
            let acknowledgement = sign_route(host, &self.offer, &self.key)?;
            let result = crate::vmproc::peer_call(&self.peer, serde_json::json!({"op":"software-route","acknowledgement":acknowledgement}))?;
            if result["status"] != "routed" {
                bail!("software route peer did not install its signed route");
            }
            Ok(())
        };
        for _ in 0..2 {
            if send().is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        send()
    }
}
