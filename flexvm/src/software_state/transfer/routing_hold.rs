//! The source packet queue outlives the stopped software VM and its TAP.
use std::fs::File;
use std::net::Ipv4Addr;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::hold::Holder;
use crate::host::{self, Backend, Flock, Host, Locked};
use crate::net;
use crate::{bail, util, util::Result};

fn notification(host: &Host, ip: Ipv4Addr) -> PathBuf {
    host.run.join("software-packet-holds").join(ip.to_string())
}

fn stamp(generation: u64, revision: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&generation.to_le_bytes());
    bytes[8..].copy_from_slice(&revision.to_le_bytes());
    bytes
}

fn notified(file: &File, expected: &[u8; 16]) -> bool {
    let mut bytes = [0; 16];
    file.read_exact_at(&mut bytes, 0).is_ok() && &bytes == expected
}

/// Called under the host lock after installing a verified signed peer route.
pub(super) fn route_installed(host: &Host, _lock: &Locked, ip: Ipv4Addr, generation: u64, revision: u64) -> Result<()> {
    let path = notification(host, ip);
    if path.try_exists()? {
        host::private_file(&path)?.write_all_at(&stamp(generation, revision), 0)?;
    }
    Ok(())
}

pub(crate) fn run(host: &Host, name: &str, timeout: Duration, ready: impl FnOnce(Value) -> Result<()>) -> Result<Value> {
    if timeout.is_zero() || timeout > Duration::from_secs(900) {
        bail!("software packet hold timeout must be between 1 and 900 seconds");
    }
    let signals = util::block_signals(&[libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT]);
    let holder = Holder::new(&format!("fsh{:x}", std::process::id()))?.ok_or("software packet hold needs /dev/net/tun")?;
    let lock = host.lock()?;
    let entry = host.entry(name)?;
    let ip = entry.ip.ok_or("software packet hold needs a routed software VM")?;
    let config = host.config_now();
    let address = config.vm_addr(ip);
    let claim = host.addr(&lock, ip)?;
    if entry.state != "running"
        || !matches!(entry.backend, Backend::QemuTcg { .. })
        || claim.holder_id.as_ref() != Some(&entry.ident)
        || claim.holder.as_deref() != Some(name)
        || claim.withdrawn
        || claim.lent.is_some()
    {
        bail!("software packet hold needs the running routed address owner");
    }
    let generation = claim.held;
    let next = host.live(&lock, ip)?.and_then(|rev| rev.checked_add(1)).ok_or("software packet hold needs a published source revision")?;
    let expected = stamp(generation, next);
    if !holder.can_replay(address) {
        bail!("software packet hold needs raw sockets for the routed address");
    }
    let path = notification(host, ip);
    let queue = Flock::new(host::private_file(&path)?, libc::LOCK_EX | libc::LOCK_NB).map_err(|error| format!("software packet hold for {ip}: {error}"))?;
    queue.0.set_len(0)?;
    let (tap, _) = net::route_get(ip.into())?;
    let tap_index = net::ifindex(&tap)?;
    let alias = host::tap_alias(&host.run, &entry.ident);
    if net::link_alias(tap_index)? != alias || address.v6.map(|ip| net::route_get(ip.into())).transpose()?.is_some_and(|(v6, _)| v6 != tap) {
        bail!("software packet hold source route does not point to the owner's TAP");
    }
    net::hold_fallback(true, address, tap_index)?;
    if let Err(error) = holder.hold(address, next) {
        if net::route(address, tap_index).is_ok() {
            let _ = net::hold_fallback(false, address, tap_index);
        }
        return Err(error);
    }
    drop(lock);

    let ready = ready(json!({"status":"holding","address":address,"generation":generation,"revision":next}));
    let deadline = Instant::now() + timeout;
    let (lock, current, forwarded) = loop {
        let finished = ready.is_err() || util::take_signal(&signals).is_some() || Instant::now() >= deadline;
        let notice = notified(&queue.0, &expected);
        if finished || notice {
            let lock = host.lock()?;
            let current = host.addr(&lock, ip)?;
            let forwarded = notified(&queue.0, &expected)
                && current.seen == generation
                && current.lent == Some(generation)
                && current.rev == next
                && current.holder.is_none()
                && !current.withdrawn;
            if finished || forwarded {
                break (lock, current, forwarded);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let same_tap = net::link_alias(tap_index).is_ok_and(|current| current == alias);
    let mut keep_fallback = false;
    let replay = (|| {
        if forwarded {
            if !host.reinstall(&lock, ip, None)? {
                bail!("software packet hold could not reinstall the signed peer route");
            }
            return Ok(json!({"status":"forwarded","hold":holder.replay_routed(ip, next)?.json()}));
        }
        if same_tap
            && current.holder_id.as_ref() == Some(&entry.ident)
            && current.held == generation
            && current.lent.is_none()
            && !current.withdrawn
            && host.live(&lock, ip)?.and_then(|rev| rev.checked_add(1)) == Some(next)
        {
            // If reinstalling the primary route fails, the fallback still
            // serves the verified source when its hold device disappears.
            keep_fallback = true;
            net::route(address, tap_index)?;
            keep_fallback = false;
            return Ok(json!({"status":"restored-source","hold":holder.replay_routed(ip, next)?.json()}));
        }
        Ok(json!({"status":"expired","hold":holder.forget(ip, next).json()}))
    })();
    if same_tap && !keep_fallback {
        let _ = net::hold_fallback(false, address, tap_index);
    }
    if replay.is_err() {
        holder.forget(ip, next);
    }
    // Under the same host lock as arming a new queue and publishing notices.
    std::fs::remove_file(&path)?;
    ready?;
    replay
}
