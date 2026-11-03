//! Holds packets for a paused VM and delivers them once it runs again, instead of letting
//! them hit a downed tap (TCP peers would wait out a retransmit timeout).
//!
//! `hold` routes the VM's /32 (and its /128, `vm_ipv6_prefix`) to this process's TUN device;
//! `release` hands the queue to a sink and switches the route. A migration streams them to the
//! target (`send`), which injects them out of the VM's tap and announces the VM only after, so
//! they come first.

use std::collections::{HashMap, VecDeque};
use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::util::{eintr, By, Result, Slot};

/// Bytes held per address; packets beyond it are dropped.
pub const CAP: usize = 4 << 20;
/// Per round of `release`, bounding catch-up with a flood faster than the sink.
const CATCH_UP: Duration = Duration::from_millis(100);
const MAX_FRAME: usize = 65535;
/// The least `gso_size` a TSO frame is cut by (TCP_MIN_MSS): a smaller one would make many
/// times its size in segments.
const MIN_MSS: usize = 88;
/// The hold device's virtio-net header (`open_tun`): struct virtio_net_hdr.
const VNET_HDR: usize = 10;
/// Packets read off the device at a time before what was read is handed over.
const PASS: usize = 256;
/// The hold device's queue length (`open_tun`).
const TXQ: usize = 10000;
/// The stream's deadlines are stretched in unit tests: there the target is a thread of a busy
/// test process, and one that misses a deadline breaks the stream the test checks (#1069).
const SLACK: u32 = if cfg!(test) { 20 } else { 1 };
const ACCEPT_WAIT: Duration = Duration::from_secs(1).saturating_mul(SLACK);
// The stream's waits for the target, as in production (`SLACK` stretches them in unit tests).
// Each that waits on the target's injections (all but `ACCEPT_WAIT`) leaves room for all it may
// wait for a full tap (`TAP_BUDGET`, for its whole stream): a guest slowly taking a backlog never
// breaks the stream (#1245).
const SYNC_WAIT_BASE: Duration = Duration::from_millis(250).saturating_add(TAP_BUDGET);
/// For the target to take the address over: a route change, which waits for RTNL. The
/// address stays held here meanwhile, so waiting loses nothing.
const SWITCH_WAIT_BASE: Duration = Duration::from_secs(2).saturating_add(TAP_BUDGET);
const FLUSH_WAIT_BASE: Duration = Duration::from_millis(400).saturating_add(TAP_BUDGET);
const REPLY_WAIT_BASE: Duration = Duration::from_secs(1).saturating_add(TAP_BUDGET);
const SYNC_WAIT: Duration = SYNC_WAIT_BASE.saturating_mul(SLACK);
const SWITCH_WAIT: Duration = SWITCH_WAIT_BASE.saturating_mul(SLACK);
const FLUSH_WAIT: Duration = FLUSH_WAIT_BASE.saturating_mul(SLACK);
const REPLY_WAIT: Duration = REPLY_WAIT_BASE.saturating_mul(SLACK);
/// How long an injection waits for a full tap's guest to take a frame (`Injector::send`): within
/// the stream's waits for the target, so a guest that stopped reading costs one such wait, not
/// one per packet.
const TAP_STALL: Duration = Duration::from_millis(200);
/// All an injector waits for a full tap, however slowly its guest takes frames: a release (an
/// address held, a tap plugged meanwhile) is bounded by it, and the stream's waits allow for it.
pub(crate) const TAP_BUDGET: Duration = Duration::from_secs(1);
/// Between tries at a full tap.
const TAP_RETRY: Duration = Duration::from_micros(200);
/// How long a let-go address's stragglers (`Holder::gone`) are re-sent or counted.
const GONE_FOR: Duration = Duration::from_secs(30);
/// Stragglers are logged at most this often per address after the first report.
const STRAGGLER_LOG: Duration = Duration::from_secs(1);

/// Where frames read off a tap go, one at a time (`Holder::hold_first`).
pub type Each<'a> = &'a mut dyn FnMut(&[u8]);

/// Where `release_local` hands packets, from more than one thread.
pub type LocalSink<'a> = &'a mut (dyn FnMut(&[u8]) -> bool + Send);

pub struct Holder {
    dev: String,
    ifindex: u32,
    tun: OwnedFd,
    /// Lookups and inserts only: no I/O under it.
    held: Mutex<HashMap<Ipv4Addr, Arc<Entry>>>,
    /// The reader has packets in hand not queued yet.
    reading: AtomicBool,
    /// Held while an address's TUN route is added or deleted.
    routes: Mutex<()>,
    /// IPv6 is on on the device (`Holder::ipv6`), off until an address with an IPv6 one is held.
    ipv6: AtomicBool,
    /// Held while a packet is read off the device and queued.
    rx: Mutex<()>,
    /// Addresses let go of. A sender that looked the route up before the switch can still
    /// hand a packet to this device after the release took the last one off it (a stalled
    /// vCPU, preemption between the lookup and the transmit): with no entry it would be lost,
    /// uncounted (#254). It is re-sent (`resend`), routed to where the address is now, or
    /// counted as dropped (`Holder::straggler`).
    gone: Mutex<HashMap<Ipv4Addr, Gone>>,
    /// Queued under `rx`, drained by one reader outside the locks, in read order.
    stragglers: Mutex<Stragglers>,
    /// A raw socket (IPPROTO_RAW: the packet's own header) the kernel routes re-sent packets by.
    resend: Option<OwnedFd>,
    /// Its IPv6 counterpart (IPPROTO_RAW implies IPV6_HDRINCL), for IPv6 stragglers.
    resend6: Option<OwnedFd>,
    /// Why there is no `resend6`, logged once IPv6 is on on the device.
    no_resend6: Option<String>,
}

#[derive(Default)]
struct Stragglers {
    packets: VecDeque<(Ipv4Addr, Gone, Vec<u8>)>,
    /// What `packets` hold, up to `CAP`: beyond it a straggler is counted as dropped.
    bytes: usize,
    draining: bool,
}

#[derive(Clone, Copy)]
struct Gone {
    at: Instant,
    /// The route moved on (a switched release), not dropped: stragglers are re-sent.
    moved: bool,
    /// Not reported yet (`report_stragglers`): re-sent, dropped.
    resent: u64,
    dropped: u64,
    reported: Option<Instant>,
    /// The hold's IPv6 address (`Entry::v6`): the only one whose stragglers are this address's.
    v6: Option<Ipv6Addr>,
}

impl Gone {
    fn new(moved: bool) -> Gone {
        Gone { at: Instant::now(), moved, resent: 0, dropped: 0, reported: None, v6: None }
    }
}

struct Entry {
    mig: u64,
    /// The IPv6 address (`vm_ipv6_prefix`) whose /128 is routed here with the /32: the only one
    /// whose packets are held for it (`ours`).
    v6: Option<Ipv6Addr>,
    q: Mutex<Queue>,
}

#[derive(Default)]
struct Queue {
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
    releasing: bool,
    /// Routed away from the device: what is still on it is bounded by the device's queue, and
    /// queued whatever `CAP` says, to be handed over.
    switched: bool,
    dropped: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    /// Handed to the sink.
    pub packets: u64,
    pub bytes: u64,
    pub dropped: u64,
    pub injected: u64,
    pub dropped_target: u64,
}

impl Stats {
    pub fn json(&self) -> Value {
        json!({"packets": self.packets, "kib": self.bytes >> 10, "dropped": self.dropped, "injected": self.injected, "dropped_target": self.dropped_target})
    }

    fn give(&mut self, sink: &mut dyn FnMut(&[u8]) -> bool, p: &[u8]) {
        match sink(p) {
            true => (self.packets, self.bytes) = (self.packets + 1, self.bytes + p.len() as u64),
            false => self.dropped += 1,
        }
    }
}

enum Switch {
    Switched,
    Refused,
    Lost(crate::util::Error),
}

/// How long the reader waits after a device error before polling again.
const READ_BACKOFF: Duration = Duration::from_millis(100);
/// How often a device error that persists is logged again.
const READ_ERROR_LOG: Duration = Duration::from_secs(60);

/// The poll events that end a wait for packets: Ok(true) readable, Ok(false) timed out, an
/// error on ERR, HUP or NVAL (never read then: an error-only event would spin).
fn poll_ready(events: i16) -> std::io::Result<bool> {
    match events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) {
        0 => Ok(events & libc::POLLIN != 0),
        bad => Err(std::io::Error::other(format!("poll events {bad:#x}"))),
    }
}

/// The reader's device errors: each backs off `READ_BACKOFF` (no spin, and a transient error
/// never ends the reader), and one that persists is logged at once, then every
/// `READ_ERROR_LOG` with a count, until a read succeeds again (never hidden for good).
#[derive(Default)]
struct ReadErrors {
    count: u64,
    logged: Option<Instant>,
}

impl ReadErrors {
    /// The line to log for this error, if one is due.
    fn failed(&mut self, e: &std::io::Error) -> Option<String> {
        self.count += 1;
        let due = self.logged.is_none_or(|t| t.elapsed() >= READ_ERROR_LOG);
        due.then(|| {
            self.logged = Some(Instant::now());
            match self.count {
                1 => format!("{e}; retrying"),
                n => format!("{e}; still failing ({n} errors); retrying"),
            }
        })
    }

    /// The line to log once a read succeeds after errors.
    fn recovered(&mut self) -> Option<String> {
        let n = std::mem::take(&mut self.count);
        self.logged = None;
        (n > 0).then(|| format!("reading again after {n} errors"))
    }
}

impl Holder {
    /// None, with a warning, without TUN support: then nothing is held.
    pub fn new(dev: &str) -> Result<Option<Arc<Holder>>> {
        let (dev, tun) = match open_tun(dev) {
            Ok(opened) => opened,
            Err((true, e)) => return Err(e),
            Err((false, e)) => {
                crate::log!("packets in flight during migrations will be dropped: {e}");
                return Ok(None);
            }
        };
        let _ = crate::net::conf("ipv6", &dev, "disable_ipv6", "1");
        crate::net::set_link_up(&dev, true)?;
        let ifindex = crate::net::ifindex(&dev)?;
        let resend = match unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_RAW) } {
            fd if fd >= 0 => Some(unsafe { OwnedFd::from_raw_fd(fd) }),
            _ => {
                crate::log!("hold device {dev}: no raw socket ({}); packets reaching it after a release are dropped", std::io::Error::last_os_error());
                None
            }
        };
        // Logged only once IPv6 is on on the device (`ipv6`): a host without IPv6 has none.
        let resend6 = match unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_RAW) } {
            fd if fd >= 0 => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
            _ => Err(std::io::Error::last_os_error()),
        };
        let no_resend6 = resend6.as_ref().err().map(ToString::to_string);
        let h = Arc::new(Holder {
            dev,
            ifindex,
            tun,
            held: Mutex::default(),
            reading: AtomicBool::new(false),
            routes: Mutex::new(()),
            ipv6: AtomicBool::new(false),
            rx: Mutex::new(()),
            gone: Mutex::default(),
            stragglers: Mutex::default(),
            resend,
            resend6: resend6.ok(),
            no_resend6,
        });
        let reader = h.clone();
        std::thread::Builder::new().name("hold".into()).spawn(move || reader.read_loop())?;
        Ok(Some(h))
    }

    /// Its IPv6 address's /128 (`vm_ipv6_prefix`) comes here with the /32, and its packets are held
    /// with the IPv4 ones, in the order they came.
    pub fn hold(&self, addr: crate::net::VmAddr, mig: u64) -> Result<()> {
        let ip = addr.v4;
        let (pending, routed) = {
            let _routes = self.routes.lock().unwrap();
            if self.held.lock().unwrap().contains_key(&ip) {
                bail!("already holding {ip}");
            }
            let v6 = addr.v6.filter(|_| self.ipv6());
            self.held.lock().unwrap().insert(ip, Arc::new(Entry { mig, v6, q: Mutex::default() }));
            let addr = crate::net::VmAddr { v4: ip, v6 };
            let routed = crate::net::route_dev(true, addr, self.ifindex);
            let pending = match &routed {
                Ok(()) => self.gone.lock().unwrap().remove(&ip),
                // Not held after all: its stragglers are still counted. Whatever of its routes got here
                // goes (by this device: never another's).
                Err(_) => {
                    let _ = crate::net::route_dev(false, addr, self.ifindex);
                    self.discard_hold(ip);
                    None
                }
            };
            (pending, routed)
        };
        // Off the locks: a blocked stderr holds up no route change or reader.
        if let Some(g) = pending {
            report(ip, &self.dev, &g);
        }
        routed
    }

    /// IPv6 on the device, the first time an address with an IPv6 address is held: off until then
    /// (`new`), so off without `vm_ipv6_prefix`. No address of its own (addr_gen_mode 1), nor router
    /// advertisements taken; what the host sends it meanwhile (MLD reports) the reader passes by
    /// (`dest`: no held address's).
    /// Failing that (IPv6 off on the host), only /32s are held, and that is logged once.
    fn ipv6(&self) -> bool {
        if self.ipv6.load(Ordering::SeqCst) {
            return true;
        }
        let on = [("addr_gen_mode", "1"), ("accept_ra", "0"), ("disable_ipv6", "0")].iter().try_for_each(|(k, v)| crate::net::conf("ipv6", &self.dev, k, v));
        match &on {
            Ok(()) => {
                if !self.ipv6.swap(true, Ordering::SeqCst) {
                    if let Some(e) = &self.no_resend6 {
                        crate::log!("hold device {}: no IPv6 raw socket ({e}); IPv6 packets reaching it after a release are dropped", self.dev);
                    }
                }
            }
            Err(e) => {
                static LOGGED: std::sync::Once = std::sync::Once::new();
                LOGGED.call_once(|| crate::log!("hold device {}: {e}: VMs' IPv6 addresses stay on their taps while held; this is logged once", self.dev));
            }
        }
        on.is_ok()
    }

    /// `unhold` once `e`'s /32 was routed elsewhere, and its /128 here with it (the switch replaces it
    /// only via a target with an IPv6 underlay, `host::route_hop`): by this device, so never one via a peer or one a VM here took meanwhile. Under
    /// `routes`, and only while `e` is still the hold, so a newer hold of `ip` keeps its /128.
    fn unhold_switched(&self, ip: Ipv4Addr, e: &Arc<Entry>) {
        let _routes = self.routes.lock().unwrap();
        let current = self.entry(ip).is_some_and(|x| Arc::ptr_eq(&x, e));
        self.unhold(ip, e, true);
        if let Some(v6) = e.v6.filter(|_| current) {
            let _ = crate::net::unroute_dev(v6.into(), self.ifindex);
        }
    }

    /// Under `routes`; `rx` keeps the reader from queuing after removal.
    fn discard_hold(&self, ip: Ipv4Addr) {
        let _rx = self.rx.lock().unwrap();
        if let Some(e) = self.held.lock().unwrap().remove(&ip) {
            let dropped = e.q.lock().unwrap().discard();
            if dropped > 0 {
                let mut gone = self.gone.lock().unwrap();
                gone.entry(ip).or_insert(Gone { v6: e.v6, ..Gone::new(false) }).dropped += dropped;
            }
        }
    }

    /// The IP packets in the frames `take` hands over, oldest first (`from_tap`, within `CAP`
    /// with what is held; the rest counted as dropped), go ahead of what is held for `ip`: routed
    /// to the VM's tap before the hold, they reached it too late for its guest to take before
    /// the pause (#379). Each frame is cut as it comes, so a backlog is never all in memory.
    pub fn hold_first(&self, ip: Ipv4Addr, mig: u64, take: impl FnOnce(Each)) {
        let Some(e) = self.entry(ip).filter(|e| e.mig == mig) else { return };
        let mut q = e.q.lock().unwrap();
        let mut first = Vec::new();
        take(&mut |f| match from_tap(f, CAP.saturating_sub(q.bytes)) {
            Some(Ok(packets)) => {
                q.bytes += packets.iter().map(Vec::len).sum::<usize>();
                first.extend(packets);
            }
            Some(Err(n)) => q.dropped += n,
            None => q.dropped += 1,
        });
        first.into_iter().rev().for_each(|p| q.packets.push_front(p));
    }

    pub fn holding_for(&self, ip: Ipv4Addr, mig: u64) -> bool {
        self.entry(ip).is_some_and(|e| e.mig == mig && !e.q.lock().unwrap().releasing)
    }

    fn entry(&self, ip: Ipv4Addr) -> Option<Arc<Entry>> {
        self.held.lock().unwrap().get(&ip).cloned()
    }

    /// None if not held or already being released.
    fn releasing(&self, ip: Ipv4Addr, mig: u64) -> Option<Arc<Entry>> {
        let e = self.entry(ip).filter(|e| e.mig == mig)?;
        let first = !std::mem::replace(&mut e.q.lock().unwrap().releasing, true);
        first.then_some(e)
    }

    /// Unless a newer hold replaced it. `moved`: the address is routed elsewhere now, where
    /// stragglers that still reach the device are re-sent.
    fn unhold(&self, ip: Ipv4Addr, e: &Arc<Entry>, moved: bool) {
        // Under `rx`: no read is between finding `e` and queuing on it, so nothing reaches its
        // queue once it is gone from `held` (what is there is then counted or handed over).
        let _rx = self.rx.lock().unwrap();
        let mut held = self.held.lock().unwrap();
        if held.get(&ip).is_some_and(|x| Arc::ptr_eq(x, e)) {
            held.remove(&ip);
            let mut gone = self.gone.lock().unwrap();
            gone.retain(|_, g| g.at.elapsed() < GONE_FOR || g.resent + g.dropped > 0);
            gone.insert(ip, Gone { v6: e.v6, ..Gone::new(moved) });
        }
    }

    /// Hands the queue to `sink` then `barrier`s (far end catching up), up to four rounds, then
    /// `switch`es and hands over the rest. `barrier` false: far end lost, but the route switches.
    /// `Switch::Refused`: the far end routes the address itself once it has
    /// all, so the route here stays until then, what reaches it counted as dropped, never
    /// removed (the address would go nowhere meanwhile) nor re-sent (it would come back).
    fn release(
        &self,
        ip: Ipv4Addr,
        mig: u64,
        sink: &mut dyn FnMut(&[u8]) -> bool,
        barrier: &mut dyn FnMut() -> bool,
        switch: impl FnOnce() -> Switch,
    ) -> Option<(Stats, Switch)> {
        let e = self.releasing(ip, mig)?;
        let mut stats = Stats::default();
        let mut lost = false;
        for _ in 0..4 {
            self.hand_over(&e, sink, &mut stats);
            if !barrier() {
                lost = true;
                break;
            }
            if e.q.lock().unwrap().packets.len() < 16 && !crate::util::readable(&self.tun, Duration::ZERO).unwrap_or(false) {
                break;
            }
        }
        let switched = switch();
        match (lost, &switched) {
            (true, _) => {}
            (false, Switch::Switched) => self.drain_switched(&e, &mut || {
                self.give_queued(&e, sink, &mut stats);
            }),
            (false, _) => {
                self.hand_over(&e, sink, &mut stats);
                // What the device took meanwhile, read here rather than left to the reader
                // (which a busy host may not run for a while): read after `unhold`, it would be a
                // straggler, counted as dropped (#539).
                if matches!(switched, Switch::Refused) {
                    self.drain(&mut || {
                        self.give_queued(&e, sink, &mut stats);
                    });
                }
            }
        }
        match switched {
            Switch::Switched => self.unhold_switched(ip, &e),
            Switch::Refused => self.unhold(ip, &e, false),
            // Left to the TUN, the address would be dropped here until the caller's retry.
            Switch::Lost(_) => self.unroute(ip, &e),
        }
        // After `unhold`: a packet read since is a straggler, re-sent (or, refused, counted),
        // not discarded here. Refused, the stream goes on, so what the reader queued after the
        // last hand-over goes too (#539).
        if !lost && !matches!(switched, Switch::Lost(_)) {
            self.give_queued(&e, sink, &mut stats);
        }
        self.finish_release(&e, &mut stats, true);
        Some((stats, switched))
    }

    /// `release` into a VM here. `switch` (a route change) may wait long, for RTNL: a helper
    /// thread hands over what arrives meanwhile. Once it is done, what the device took before
    /// it is read off it right away (not waiting for the reader thread, which a busy host may
    /// not run for a while), so the packets routed to the VM from then on have as little as
    /// possible to overtake, and handed over a pass at a time, so a backlog is delivered
    /// rather than dropped at `CAP`. Nothing held is dropped for taking long, and traffic that
    /// keeps arriving never holds the switch up: each hand-over takes only what was queued when
    /// it began, and reading after the switch stops at the device's queue length. With
    /// `linger`, the device is then watched that long more for a packet from a sender that
    /// looked the old route up just before the switch. If `switch` fails the address stays
    /// held until `forget`.
    pub fn release_local(&self, ip: Ipv4Addr, mig: u64, sink: LocalSink, switch: impl FnOnce() -> Result<()>, linger: Duration) -> Option<(Stats, Result<()>)> {
        let e = self.releasing(ip, mig)?;
        let out = Mutex::new((sink, Stats::default()));
        let give = |o: &mut (LocalSink, Stats)| self.give_queued(&e, &mut *o.0, &mut o.1);
        give(&mut out.lock().unwrap());
        // `release_late`: the hand-over is held up from 20 ms before the switch to 30 ms after
        // it, as a busy host may (packets the device took before the switch are still here
        // when routed ones reach the VM).
        let late = crate::host::fault("release_late");
        if late {
            std::thread::sleep(Duration::from_millis(20));
        }
        let switching = AtomicBool::new(!late);
        let mut buf = vec![0u8; VNET_HDR + MAX_FRAME];
        let switched = std::thread::scope(|sc| {
            if let Err(e) = std::thread::Builder::new().name("hold-release".into()).spawn_scoped(sc, || {
                while switching.load(Ordering::SeqCst) {
                    if !give(&mut out.lock().unwrap()) {
                        std::thread::sleep(Duration::from_micros(200));
                    }
                }
            }) {
                // Continue the switch and drain inline below; the reader still queues arrivals.
                crate::log!("hold {ip}: releasing without a hand-over helper: {e}");
            }
            let switched = switch();
            if late {
                std::thread::sleep(Duration::from_millis(30));
            }
            // Right away, here: the helper may be asleep, or not running at all.
            let mut o = out.lock().unwrap();
            if switched.is_ok() {
                self.drain_switched(&e, &mut || {
                    give(&mut o);
                });
            }
            switching.store(false, Ordering::SeqCst);
            switched
        });
        let mut o = out.into_inner().unwrap();
        if switched.is_ok() {
            let end = Instant::now() + linger;
            while Instant::now() < end {
                if crate::util::readable(&self.tun, end.saturating_duration_since(Instant::now()).max(Duration::from_millis(1))).unwrap_or(false) {
                    (0..PASS).take_while(|_| self.read_one(&mut buf)).count();
                }
                give(&mut o);
            }
        }
        if switched.is_ok() {
            self.unhold_switched(ip, &e);
        }
        // After `unhold`: a packet read since is a straggler, re-sent, not discarded below.
        give(&mut o);
        let mut stats = o.1;
        self.finish_release(&e, &mut stats, switched.is_ok());
        Some((stats, switched))
    }

    fn finish_release(&self, e: &Entry, stats: &mut Stats, discard: bool) {
        let mut q = e.q.lock().unwrap();
        stats.dropped += if discard { q.discard() } else { std::mem::take(&mut q.dropped) };
        drop(q);
        self.report_stragglers();
    }

    /// Routed away, nothing new reaches the device for the address: what it took is read off it
    /// here (the reader thread may not run for a while on a busy host), a pass at a time, each
    /// `give`n before the next, up to its queue length, so no flood can make it more.
    fn drain_switched(&self, e: &Entry, give: &mut dyn FnMut()) {
        e.q.lock().unwrap().switched = true;
        self.drain(give);
    }

    /// Reads the device a pass at a time, each `give`n before the next, until it is empty or up
    /// to its queue length (a flood still routed here never holds it up longer).
    fn drain(&self, give: &mut dyn FnMut()) {
        let mut buf = vec![0u8; VNET_HDR + MAX_FRAME];
        for read in (0..TXQ).step_by(PASS) {
            let pass = PASS.min(TXQ - read);
            let n = (0..pass).take_while(|_| self.read_one(&mut buf)).count();
            give();
            if n < pass {
                break;
            }
        }
    }

    /// Hands over what is queued now, not what arrives meanwhile; false if there was none.
    fn give_queued(&self, e: &Entry, sink: &mut dyn FnMut(&[u8]) -> bool, stats: &mut Stats) -> bool {
        let mut left = e.q.lock().unwrap().packets.len();
        let any = left > 0;
        while left > 0 {
            let batch = e.q.lock().unwrap().take_batch();
            if batch.is_empty() {
                break;
            }
            left = left.saturating_sub(batch.len());
            batch.iter().for_each(|p| stats.give(sink, p));
        }
        any
    }

    fn hand_over(&self, e: &Entry, sink: &mut dyn FnMut(&[u8]) -> bool, stats: &mut Stats) {
        let end = Instant::now() + CATCH_UP;
        while Instant::now() < end {
            let batch = e.q.lock().unwrap().take_batch();
            if batch.is_empty() {
                if !self.reading.load(Ordering::SeqCst) && !crate::util::readable(&self.tun, Duration::ZERO).unwrap_or(false) {
                    return;
                }
                std::thread::yield_now();
                continue;
            }
            let mut rest = batch.into_iter();
            for p in rest.by_ref() {
                stats.give(sink, &p);
                if Instant::now() >= end {
                    break;
                }
            }
            let mut q = e.q.lock().unwrap();
            for p in rest.rev() {
                q.bytes += p.len();
                q.packets.push_front(p);
            }
        }
    }

    pub fn forget(&self, ip: Ipv4Addr, mig: u64) -> Stats {
        let Some(e) = self.entry(ip).filter(|e| e.mig == mig) else { return Stats::default() };
        self.unroute(ip, &e);
        let dropped = e.q.lock().unwrap().discard();
        Stats { dropped, ..Stats::default() }
    }

    /// Drops `e` and its TUN route, unless a newer hold replaced it.
    fn unroute(&self, ip: Ipv4Addr, e: &Arc<Entry>) {
        // Under `routes`: a newer hold of `ip` never loses its route to this one.
        let _routes = self.routes.lock().unwrap();
        if self.entry(ip).is_some_and(|x| Arc::ptr_eq(&x, e)) {
            self.unhold(ip, e, false);
            let _ = crate::net::route_dev(false, crate::net::VmAddr { v4: ip, v6: e.v6 }, self.ifindex);
        }
    }

    fn read_loop(&self) {
        let mut pfd = libc::pollfd { fd: self.tun.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let mut buf = vec![0u8; VNET_HDR + MAX_FRAME];
        let mut wait = -1;
        let mut errors = ReadErrors::default();
        loop {
            let failed = match eintr(|| unsafe { libc::poll(&mut pfd, 1, wait) }).and_then(|_| poll_ready(pfd.revents)) {
                Ok(true) => {
                    self.reading.store(true, Ordering::SeqCst);
                    // Due reports also go out under sustained traffic, not only once the device is empty.
                    let mut n = 0usize;
                    let read = loop {
                        match self.try_read_one(&mut buf) {
                            Ok(true) => n += 1,
                            Ok(false) => break Ok(()),
                            Err(e) => break Err(e),
                        }
                        if n % PASS == 0 {
                            self.report_stragglers();
                        }
                    };
                    self.reading.store(false, Ordering::SeqCst);
                    if n > 0 {
                        if let Some(line) = errors.recovered() {
                            crate::log!("hold device {}: {line}", self.dev);
                        }
                    }
                    read.err()
                }
                Ok(false) => None,
                Err(e) => Some(e),
            };
            if let Some(e) = failed {
                if let Some(line) = errors.failed(&e) {
                    crate::log!("hold device {}: {line}", self.dev);
                }
                std::thread::sleep(READ_BACKOFF);
            }
            wait = self.report_stragglers();
        }
    }

    /// Logs every straggler counted and not reported yet, whenever the last report was: for a
    /// process about to end, whose rate-limited reports would otherwise never come.
    pub fn report_now(&self) {
        self.gone.lock().unwrap().values_mut().for_each(|g| g.reported = None);
        self.report_stragglers();
    }

    /// Logs the stragglers counted since an address's last report: the first report at once,
    /// later ones at most every `STRAGGLER_LOG`. Here, off `rx`: a blocked stderr never holds
    /// up reading the device or a release. Returns the reader's poll timeout (ms): until the
    /// next report is due, or at most `STRAGGLER_LOG` while any let-go address is remembered
    /// (a release's own reads may count stragglers meanwhile), else -1.
    fn report_stragglers(&self) -> i32 {
        let mut due: Option<Duration> = None;
        let mut gone = self.gone.lock().unwrap();
        let ready: Vec<_> = gone
            .iter_mut()
            .filter(|(_, g)| g.resent + g.dropped > 0)
            .filter_map(|(ip, g)| match g.reported.map(|r| STRAGGLER_LOG.saturating_sub(r.elapsed())).filter(|d| !d.is_zero()) {
                Some(d) => {
                    due = Some(due.map_or(d, |x| x.min(d)));
                    None
                }
                None => {
                    let out = (*ip, *g);
                    (g.resent, g.dropped, g.reported) = (0, 0, Some(Instant::now()));
                    Some(out)
                }
            })
            .collect();
        gone.retain(|_, g| g.at.elapsed() < GONE_FOR || g.resent + g.dropped > 0);
        let watching = !gone.is_empty();
        drop(gone);
        ready.iter().for_each(|(ip, g)| report(*ip, &self.dev, g));
        match (due, watching) {
            (Some(d), _) => d.min(STRAGGLER_LOG).as_millis().max(1) as i32,
            (None, true) => STRAGGLER_LOG.as_millis() as i32,
            (None, false) => -1,
        }
    }

    /// Reads a packet off the device and queues it for its address; false once it is empty.
    /// Read and queued under `rx`, so packets are queued in the order they were read, by
    /// whichever thread.
    fn read_one(&self, buf: &mut [u8]) -> bool {
        self.try_read_one(buf).unwrap_or(false)
    }

    /// `read_one`, with the device's error: the reader backs off on it, a release's drain stops.
    fn try_read_one(&self, buf: &mut [u8]) -> std::io::Result<bool> {
        let _rx = self.rx.lock().unwrap();
        let n = match eintr(|| unsafe { libc::read(self.tun.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) }) {
            Ok(0) => return Err(std::io::Error::other("read returned nothing")),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e),
        };
        // #362: a guest frame with VIRTIO_NET_HDR_F_NEEDS_CSUM can aim checksum completion at
        // its own IP source, after the tap's ingress filter passed the original. The device
        // leaves completion to us (`open_tun`): `accept` does it only at a TCP or UDP checksum
        // field, so no forged source is queued, nor re-sent by `straggler` (whose IPPROTO_RAW
        // resend recomputes the header checksum; IPv6 has none, and `accept6` writes nowhere
        // in its fixed header either).
        // Refused, it is counted as dropped for the address it was sent to, if it has one.
        let Some((h, p)) = buf[..n as usize].split_at_mut_checked(VNET_HDR) else { return Ok(true) };
        let Some((ip, to6)) = dest(p) else { return Ok(true) };
        if !accept_ip(h, 0, p) {
            self.refused(ip, to6);
            return Ok(true);
        }
        let drain = match self.entry(ip).filter(|e| ours(e.v6, to6)) {
            Some(e) => {
                let mut q = e.q.lock().unwrap();
                if q.bytes + p.len() > CAP && !q.switched {
                    q.dropped += 1;
                } else {
                    q.bytes += p.len();
                    q.packets.push_back(p.to_vec());
                }
                false
            }
            None => self.straggler(ip, p),
        };
        drop(_rx);
        if drain {
            self.drain_stragglers(|ip, p| self.resend(ip, p));
        }
        Ok(true)
    }

    /// A packet for `ip` (IPv6: `to6`) that `accept` refused: dropped where `ip`'s packets are
    /// counted, held or let go of (then reported as a straggler). Under `rx`.
    fn refused(&self, ip: Ipv4Addr, to6: Option<Ipv6Addr>) {
        match self.entry(ip).filter(|e| ours(e.v6, to6)) {
            Some(e) => e.q.lock().unwrap().dropped += 1,
            None => {
                if let Some(g) = self.gone.lock().unwrap().get_mut(&ip).filter(|g| g.at.elapsed() < GONE_FOR && ours(g.v6, to6)) {
                    g.dropped += 1;
                }
            }
        }
    }

    /// A packet for `ip` read after it was let go of: re-sent if the address moved on, else
    /// counted (and logged by `report_stragglers`, not here: this runs under `rx`). Its TTL
    /// (IPv6: hop limit) goes down by one, so a route that still leads here cannot loop it.
    /// Limits, each counted as dropped: a fragment with IP ID 0 (the kernel would give it a new
    /// ID, so it would no longer reassemble with its siblings; no IPv6 fragment gets this far,
    /// `accept6`), and a packet larger than the new route's MTU (EMSGSIZE). A re-sent packet can
    /// arrive after newer ones that took the new route (and behind what a plugged tap holds):
    /// late rather than lost. An `accept`ed packet; an IPv6 one only for the hold's own /128.
    /// Queues under `rx`; true gives this reader the drain, after it drops `rx`.
    fn straggler(&self, ip: Ipv4Addr, p: &mut [u8]) -> bool {
        let to6 = dest(p).and_then(|(_, to6)| to6);
        let mut gone = self.gone.lock().unwrap();
        let Some(g) = gone.get_mut(&ip).filter(|g| g.at.elapsed() < GONE_FOR && ours(g.v6, to6)) else { return false };
        let (hops, resend) = match to6 {
            Some(_) => (7, &self.resend6),
            None => (8, &self.resend),
        };
        let fragment = to6.is_none() && u16::from_be_bytes([p[6], p[7]]) & 0x3fff != 0;
        let zero_id = p[4] == 0 && p[5] == 0;
        let mut q = self.stragglers.lock().unwrap();
        if !g.moved || (fragment && zero_id) || p[hops] <= 1 || resend.is_none() || q.bytes + p.len() > CAP {
            g.dropped += 1;
            return false;
        }
        p[hops] -= 1;
        q.bytes += p.len();
        q.packets.push_back((ip, Gone { resent: 1, dropped: 0, ..*g }, p.to_vec()));
        !std::mem::replace(&mut q.draining, true)
    }

    fn drain_stragglers(&self, mut send: impl FnMut(Ipv4Addr, &[u8]) -> bool) {
        // Counts whose record went meanwhile, one report per run of a record's packets.
        let mut orphaned: Option<(Ipv4Addr, Gone)> = None;
        loop {
            let next = {
                let mut q = self.stragglers.lock().unwrap();
                let next = q.packets.pop_front();
                q.bytes -= next.as_ref().map_or(0, |(_, _, p)| p.len());
                q.draining = next.is_some();
                next
            };
            let Some((ip, count, p)) = next else { break };
            let sent = send(ip, &p);
            let Some(c) = self.count_straggler(ip, count, sent) else { continue };
            match &mut orphaned {
                Some((o, g)) if *o == ip && g.at == c.at => (g.resent, g.dropped) = (g.resent + c.resent, g.dropped + c.dropped),
                _ => {
                    if let Some((o, g)) = orphaned.replace((ip, c)) {
                        report(o, &self.dev, &g);
                    }
                }
            }
        }
        if let Some((ip, g)) = orphaned {
            report(ip, &self.dev, &g);
        }
    }

    /// Returns counts to report here if a new hold or expiry removed the original record.
    fn count_straggler(&self, ip: Ipv4Addr, mut count: Gone, sent: bool) -> Option<Gone> {
        if !sent {
            (count.resent, count.dropped) = (0, 1);
        }
        let mut gone = self.gone.lock().unwrap();
        match gone.get_mut(&ip).filter(|g| g.at == count.at) {
            Some(g) => {
                g.resent += count.resent;
                g.dropped += count.dropped;
                None
            }
            None => Some(count),
        }
    }

    /// IPv6 (its destination, `dest`) by `resend6`: the kernel adds no header, nor checksums it.
    fn resend(&self, ip: Ipv4Addr, p: &[u8]) -> bool {
        if let Some((_, Some(to6))) = dest(p) {
            return self.resend6.as_ref().is_some_and(|fd| {
                let to = sockaddr6(to6);
                let size = std::mem::size_of::<libc::sockaddr_in6>() as u32;
                unsafe { libc::sendto(fd.as_raw_fd(), p.as_ptr().cast(), p.len(), libc::MSG_DONTWAIT, (&to as *const libc::sockaddr_in6).cast(), size) >= 0 }
            });
        }
        self.resend.as_ref().is_some_and(|fd| {
            // The kernel fills the header checksum in.
            let mut to: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            to.sin_family = libc::AF_INET as u16;
            to.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
            let size = std::mem::size_of::<libc::sockaddr_in>() as u32;
            unsafe { libc::sendto(fd.as_raw_fd(), p.as_ptr().cast(), p.len(), libc::MSG_DONTWAIT, (&to as *const libc::sockaddr_in).cast(), size) >= 0 }
        })
    }
}

/// The address a packet off the hold device is for: an IPv4 one's destination, or the IPv4
/// address in an IPv6 one's low 32 bits (`vm_ipv6_prefix`) with that destination, which must be
/// the hold's own (`ours`). None if too short for its header.
fn dest(p: &[u8]) -> Option<(Ipv4Addr, Option<Ipv6Addr>)> {
    match p.first()? >> 4 {
        6 => {
            let to: [u8; 16] = p.get(24..40)?.try_into().ok()?;
            Some((Ipv4Addr::new(to[12], to[13], to[14], to[15]), Some(to.into())))
        }
        _ => (p.len() >= 20).then(|| Ipv4Addr::new(p[16], p[17], p[18], p[19])).map(|ip| (ip, None)),
    }
}

/// Whether a packet for `to6` (None: IPv4) is for the hold (or let-go address) whose IPv6 address
/// is `v6`: an IPv6 one only for exactly that /128, never another whose low 32 bits are the same
/// (another prefix's, the host's own multicast).
fn ours(v6: Option<Ipv6Addr>, to6: Option<Ipv6Addr>) -> bool {
    to6.is_none() || to6 == v6
}

fn sockaddr6(to: Ipv6Addr) -> libc::sockaddr_in6 {
    // Port 0: the socket's own protocol (IPPROTO_RAW, the packet's header).
    let mut a: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    a.sin6_family = libc::AF_INET6 as u16;
    a.sin6_addr.s6_addr = to.octets();
    a
}

/// Whether `p`'s IPv4 header checksum is valid (the one's-complement sum over the header,
/// including its own checksum field, is 0xffff). The header length is `p[0] & 0xf` 32-bit
/// words; a truncated or under-length header is treated as invalid.
fn ipv4_header_csum_ok(p: &[u8]) -> bool {
    let ihl = (p[0] & 0xf) as usize * 4;
    ihl >= 20 && p.len() >= ihl && sum16(&p[..ihl]) == 0xffff
}

/// The one's-complement sum of `b` as big-endian 16-bit words (an odd last byte padded), folded.
fn sum16(b: &[u8]) -> u16 {
    let mut sum: u32 = b.chunks(2).map(|w| u32::from(u16::from_be_bytes([w[0], w.get(1).copied().unwrap_or(0)]))).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// The IP packets in a frame read off a tap (a 12-byte virtio-net header, then Ethernet),
/// each `accept`ed (IPv6: `accept6`): one, or a TCP GSO frame's segments (Firecracker turns TSO
/// on for a guest that takes it, as Linux does: a bulk download's frames are mostly these,
/// #411), cut as `tcp_gso_segment` would. None for anything else (UDP GSO, ARP, a `gso_size`
/// under `MIN_MSS`); Err(how many) if they would take more than `room` bytes.
fn from_tap(f: &[u8], room: usize) -> Option<std::result::Result<Vec<Vec<u8>>, u64>> {
    let (h, eth) = (f.get(..12)?, f.get(12..)?);
    let v6 = eth.get(12..14)? == [0x86, 0xdd];
    let len = match v6 {
        false => usize::from(u16::from_be_bytes([*eth.get(16)?, *eth.get(17)?])),
        true => 40 + usize::from(u16::from_be_bytes([*eth.get(18)?, *eth.get(19)?])),
    };
    let mut p = eth.get(14..14 + len)?.to_vec();
    if !v6 && eth[12..14] != [8, 0] {
        return None;
    }
    let accept = if v6 { accept6 } else { accept };
    // `h` as for one packet: what each segment must pass, and the whole frame first.
    let one = [&[h[0], 0][..], &h[2..]].concat();
    match (v6, h[1] & 0x7f) {
        // An IPv6 packet may be 40 bytes longer than an IPv4 one: never more than a frame (`valid`).
        (_, 0) => return (h[1] == 0 && (!v6 || p.len() <= MAX_FRAME) && accept(h, 14, &mut p)).then(|| if p.len() <= room { Ok(vec![p]) } else { Err(1) }),
        // TCPv4 (0x80: ECN), its checksum left to the device: only in TCP's own field.
        (false, 1) if p.get(9) == Some(&6) && h[0] & 1 != 0 && accept(&one, 14, &mut p.clone()) => {}
        // TCPv6, right after the fixed header (`accept6`), likewise.
        (true, 4) if p.get(6) == Some(&6) && h[0] & 1 != 0 && accept(&one, 14, &mut p.clone()) => {}
        _ => return None,
    }
    let (ihl, mss) = (if v6 { 40 } else { usize::from(p[0] & 0xf) * 4 }, usize::from(u16::from_le_bytes([h[4], h[5]])));
    let thl = usize::from(*p.get(ihl + 12)? >> 4) * 4;
    let (head, body) = p.split_at_checked(ihl + thl)?;
    if mss < MIN_MSS || thl < 20 || body.is_empty() {
        return None;
    }
    // Nor a segment of more than a frame (whose length would not fit its own fields).
    if v6 && head.len() + mss.min(body.len()) > MAX_FRAME {
        return None;
    }
    let (id, seq, n) = (u16::from_be_bytes([p[4], p[5]]), u32::from_be_bytes(p[ihl + 4..ihl + 8].try_into().ok()?), body.len().div_ceil(mss));
    // Sized before any is made: each segment repeats the headers.
    if body.len() + n * head.len() > room {
        return Some(Err(n as u64));
    }
    let segment = |(i, data): (usize, &[u8])| {
        let mut s = [head, data].concat();
        let len = s.len() as u16;
        if v6 {
            // Its payload length; no ID (an IPv6 one is in a fragment header), no header checksum.
            s[4..6].copy_from_slice(&(len - 40).to_be_bytes());
        } else {
            s[2..4].copy_from_slice(&len.to_be_bytes());
            s[4..6].copy_from_slice(&id.wrapping_add(i as u16).to_be_bytes());
            s[10..12].fill(0);
            let sum = !sum16(&s[..ihl]);
            s[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        s[ihl + 4..ihl + 8].copy_from_slice(&seq.wrapping_add((i * mss) as u32).to_be_bytes());
        // FIN and PSH on the last segment only, CWR on the first.
        s[ihl + 13] &= !(if i + 1 < n { 0x09 } else { 0 } | if i > 0 { 0x80 } else { 0 });
        // The pseudo-header's sum where the checksum goes, for `accept` to complete.
        let pseudo = match v6 {
            false => sum16(&[&s[12..20], &[0, 6], &(len - ihl as u16).to_be_bytes()].concat()),
            true => sum16(&[&s[8..40], &[0, 0], &(len - 40).to_be_bytes(), &[0, 0, 0, 6]].concat()),
        };
        s[ihl + 16..ihl + 18].copy_from_slice(&pseudo.to_be_bytes());
        accept(&one, 14, &mut s).then_some(s)
    };
    body.chunks(mss).enumerate().map(segment).collect::<Option<_>>().map(Ok)
}

/// Whether IPv4 packet `p`, behind virtio-net header `h`, may go to a guest or be re-sent,
/// its L4 checksum completed if `h` leaves that to the device (as `skb_checksum_help` would).
/// Completed only in a TCP or UDP packet's own checksum field, its `csum_start` right after
/// the IP header (`eth`: the bytes before that header it counts): anywhere else a guest could
/// aim the write at the header and forge a source the header checksum still passes (#406:
/// 0x0000 to 0xffff across the middle bytes of 10.0.0.2). Then the header checksum must
/// verify (`ipv4_header_csum_ok`). Not GSO (many packets in one).
fn accept(h: &[u8], eth: usize, p: &mut [u8]) -> bool {
    if p.len() < 20 || p[0] >> 4 != 4 || h[1] != 0 {
        return false;
    }
    if h[0] & 1 != 0 {
        let ihl = usize::from(p[0] & 0xf) * 4;
        let Some(field) = (match p[9] {
            6 => Some(16),
            17 => Some(6),
            _ => None,
        }) else {
            return false;
        };
        let (start, off) = (usize::from(u16::from_le_bytes([h[6], h[7]])), usize::from(u16::from_le_bytes([h[8], h[9]])));
        if start != eth + ihl || off != field || ihl < 20 || p.len() < ihl + field + 2 {
            return false;
        }
        let sum = !sum16(&p[ihl..]);
        p[ihl + field..ihl + field + 2].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
    }
    ipv4_header_csum_ok(p)
}

/// Whether IPv6 packet `p` is whole (its payload length all the rest of it) and what follows its
/// fixed header may be held, injected or re-sent: TCP or UDP (Some: where in it its checksum is),
/// or ICMPv6 but neighbour discovery (None), which is the link's own, never routed. No extension
/// header: hop-by-hop or destination options and routing headers are what the tap's guard keeps
/// a guest from sending too, and a fragment header would hide what follows it.
fn upper6(p: &[u8]) -> Option<Option<usize>> {
    if p.len() < 40 || p[0] >> 4 != 6 || usize::from(u16::from_be_bytes([p[4], p[5]])) + 40 != p.len() {
        return None;
    }
    match p[6] {
        6 => Some(Some(16)),
        17 => Some(Some(6)),
        // Router solicitations and advertisements, neighbour solicitations and advertisements, redirects.
        58 => p.get(40).filter(|t| !(133..=137).contains(*t)).map(|_| None),
        _ => None,
    }
}

/// `accept` for an IPv6 packet (`upper6`). A checksum left to the device is completed only in a
/// TCP or UDP packet's own field, `csum_start` right after the fixed header (none in it is
/// checksummed, so nothing else would catch a write there). Not GSO.
fn accept6(h: &[u8], eth: usize, p: &mut [u8]) -> bool {
    let Some(field) = upper6(p).filter(|_| h[1] == 0) else { return false };
    if h[0] & 1 != 0 {
        let Some(field) = field else { return false };
        let (start, off) = (usize::from(u16::from_le_bytes([h[6], h[7]])), usize::from(u16::from_le_bytes([h[8], h[9]])));
        if start != eth + 40 || off != field || p.len() < 40 + field + 2 {
            return false;
        }
        let sum = !sum16(&p[40..]);
        p[40 + field..40 + field + 2].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
    }
    true
}

/// `accept` or `accept6`, by `p`'s version.
fn accept_ip(h: &[u8], eth: usize, p: &mut [u8]) -> bool {
    match p.first().map(|b| b >> 4) {
        Some(6) => accept6(h, eth, p),
        _ => accept(h, eth, p),
    }
}

/// Logs `g`'s straggler counts, if any ("dropped N" is what loss accounting reads).
fn report(ip: Ipv4Addr, dev: &str, g: &Gone) {
    let after = format!("{dev} after it let go of the address ({} ms ago)", g.at.elapsed().as_millis());
    match (g.resent, g.dropped) {
        (0, 0) => {}
        (r, 0) => crate::info!("hold {ip}: re-sent {r} packets that reached {after}"),
        (r, d) => crate::info!("hold {ip}: dropped {d} packets that reached {after}, re-sent {r}"),
    }
}

impl Queue {
    fn take_batch(&mut self) -> Vec<Vec<u8>> {
        let batch: Vec<_> = self.packets.drain(..self.packets.len().min(256)).collect();
        self.bytes -= batch.iter().map(Vec::len).sum::<usize>();
        batch
    }

    /// Empties it, counting what is thrown away as dropped.
    fn discard(&mut self) -> u64 {
        let n = std::mem::take(&mut self.dropped) + self.packets.len() as u64;
        (self.packets, self.bytes) = Default::default();
        n
    }
}

/// Sends IP packets to a guest as Ethernet frames out of its tap, as Firecracker would.
pub struct Injector {
    fd: OwnedFd,
    tap: String,
    ifindex: u32,
    /// The frames' MACs; the ethertype is each packet's (`ethertype`).
    header: [u8; 12],
    tx_dropped: u64,
    /// Sends a full tap refused (`ENOBUFS`), each also in its `tx_dropped`: tried again, or
    /// counted by the caller as dropped, never in `dropped` (#1245).
    refused: AtomicU64,
    wait: Mutex<Wait>,
}

/// Whether an injector waits for a full tap's guest (`Injector::send`).
#[derive(Debug)]
struct Wait {
    /// When the tap last took a frame (or the injector was made).
    took: Instant,
    /// All it waited so far, within `TAP_BUDGET`.
    waited: Duration,
    /// It no longer waits: its guest is not running, stalled for `TAP_STALL` or took the budget.
    single: bool,
}

impl Wait {
    fn new(waits: bool) -> Wait {
        Wait { took: Instant::now(), waited: Duration::ZERO, single: !waits }
    }

    /// Whether a refused frame is tried again: once not, never again.
    fn again(&mut self) -> bool {
        if !self.single && (self.took.elapsed() >= TAP_STALL || self.waited >= TAP_BUDGET) {
            self.single = true;
        }
        !self.single
    }
}

impl Injector {
    /// `waits`: a refused frame waits for the guest to take one (only while it runs: a paused one
    /// takes none, and its resume waits for the injection).
    pub fn new(tap: &str, waits: bool) -> Result<Injector> {
        // Protocol 0: it sends and never receives.
        let fd = eintr(|| unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) }).map_err(|e| format!("packet socket: {e}"))?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // Past the tap's qdisc, straight to the tap: ahead of what a plugged qdisc holds back
        // (`net::plug_tap`). Without it (older kernels) the frames queue there too.
        const SOL_PACKET: libc::c_int = 263;
        const PACKET_QDISC_BYPASS: libc::c_int = 20;
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(fd.as_raw_fd(), SOL_PACKET, PACKET_QDISC_BYPASS, (&one as *const libc::c_int).cast(), std::mem::size_of::<libc::c_int>() as u32)
        };
        let mut header = [0u8; 12];
        header[..6].copy_from_slice(&crate::net::GUEST_MAC);
        header[6..12].copy_from_slice(&crate::net::GATEWAY_MAC);
        Ok(Injector {
            fd,
            tap: tap.into(),
            ifindex: crate::net::ifindex(tap)?,
            header,
            tx_dropped: tap_tx_dropped(tap).unwrap_or(0),
            refused: AtomicU64::new(0),
            wait: Mutex::new(Wait::new(waits)),
        })
    }

    pub fn send(&self, packet: &[u8]) -> bool {
        let ethertype = ethertype(packet);
        let header: [u8; 14] = std::array::from_fn(|i| if i < 12 { self.header[i] } else { ethertype.to_be_bytes()[i - 12] });
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = self.ifindex as i32;
        addr.sll_protocol = ethertype.to_be();
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&self.header[..6]);
        let mut iov = [
            libc::iovec { iov_base: header.as_ptr().cast_mut().cast(), iov_len: header.len() },
            libc::iovec { iov_base: packet.as_ptr().cast_mut().cast(), iov_len: packet.len() },
        ];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&mut addr as *mut libc::sockaddr_ll).cast();
        msg.msg_namelen = std::mem::size_of_val(&addr) as u32;
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len();
        let len = (header.len() + packet.len()) as isize;
        // A tap queues only so many frames (its txqueuelen) for its guest to take: a hold's backlog
        // can be more, injected faster than a guest takes them. Refused, the frame waits for the
        // guest to make room, while it takes any within `TAP_STALL`, within `TAP_BUDGET` (#1245).
        loop {
            let n = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &msg, libc::MSG_DONTWAIT) };
            if n == len {
                self.wait.lock().unwrap().took = Instant::now();
                return true;
            }
            if n >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOBUFS) {
                return false;
            }
            self.refused.fetch_add(1, Ordering::Relaxed);
            if !self.wait.lock().unwrap().again() {
                return false;
            }
            let slept = Instant::now();
            std::thread::sleep(TAP_RETRY);
            self.wait.lock().unwrap().waited += slept.elapsed();
        }
    }

    /// Dropped by the tap since this was made (with the guest's own traffic), but for the sends it
    /// refused (`refused`), which the caller counts: reported with the injected packets.
    pub fn dropped(&self) -> u64 {
        tap_tx_dropped(&self.tap).unwrap_or(0).saturating_sub(self.tx_dropped).saturating_sub(self.refused())
    }

    /// The sends the full tap refused, each in its `tx_dropped` (`Vm::tap_drops_reported`).
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }
}

/// An injected packet's ethertype: IPv6 by its version, else IPv4 (all else `valid` refuses).
fn ethertype(packet: &[u8]) -> u16 {
    match packet.first().map(|b| b >> 4) {
        Some(6) => 0x86dd,
        _ => 0x0800,
    }
}

pub(crate) fn tap_tx_dropped(tap: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/class/net/{tap}/statistics/tx_dropped")).ok().and_then(|s| s.trim().parse().ok())
}

// Stream (over TCP: nothing lost or reordered): `START`, answered `b'a'`. Frames: u32 BE
// length, packet. `SYNC` gets `b's'` once all before it is injected. `SWITCH` (hosts sharing
// routes) gets `b'w'` once all before it is injected and the target took the address over,
// `b'n'` if it could not (the stream goes on: the target routes the address once it ends).
// Length 0 ends it and gets one JSON line. Nothing is resent.
const SYNC: u32 = u32::MAX;
/// Not `u32::MAX - 1`, which started the stream with sequence numbers: a target here refuses
/// such a source's stream (which counts its packets dropped), never misreads it.
const START: u32 = u32::MAX - 3;
const SWITCH: u32 = u32::MAX - 2;
const MAX_RECEIVERS: usize = 8;
static RECEIVERS: AtomicUsize = AtomicUsize::new(0);

fn read_by(r: &mut BufReader<By<TcpStream>>, buf: &mut [u8], deadline: Instant) -> std::io::Result<()> {
    r.get_mut().at = deadline;
    r.read_exact(buf)
}

fn write_by(w: &TcpStream, buf: &[u8], deadline: Instant) -> std::io::Result<()> {
    By { s: w, at: deadline }.write_all(buf)
}

pub fn wait_start(r: &mut BufReader<By<TcpStream>>, deadline: Instant) -> bool {
    let mut head = [0u8; 4];
    read_by(r, &mut head, deadline).is_ok() && u32::from_be_bytes(head) == START
}

/// Injects only while `revoked` is false; on `SWITCH`, `take_over` takes the address (false if it
/// could not, which the source is told). Refused if too many streams are being received.
/// `running`: its guest runs, so a full tap is waited for (`Injector::new`).
/// Returns how many of the tap's drops it accounted for: its refused sends (`Injector::refused`),
/// whether or not the stream ended, and the rest (`Injector::dropped`) once it reported them.
pub fn receive(
    r: &mut BufReader<By<TcpStream>>,
    addr: crate::net::VmAddr,
    tap: &str,
    running: bool,
    revoked: &Mutex<bool>,
    deadline: Instant,
    take_over: &mut dyn FnMut() -> bool,
) -> u64 {
    let Some(_slot) = Slot::take(&RECEIVERS, MAX_RECEIVERS) else { return 0 };
    let (Ok(conn), Ok(inj)) = (r.get_ref().s.try_clone(), Injector::new(tap, running)) else { return 0 };
    if write_by(&conn, b"a", deadline).is_err() {
        return 0;
    }
    let (mut buf, mut injected, mut dropped) = (vec![0u8; MAX_FRAME], 0, 0);
    let ended = loop {
        let mut head = [0u8; 4];
        if read_by(r, &mut head, deadline).is_err() {
            break false;
        }
        let len = match u32::from_be_bytes(head) {
            SYNC if write_by(&conn, b"s", deadline).is_ok() => continue,
            SYNC => break false,
            SWITCH => {
                // What was injected before is queued on the tap ahead of anything routed.
                let took = take_over();
                match write_by(&conn, if took { b"w" } else { b"n" }, deadline) {
                    Ok(()) => continue,
                    Err(_) => break false,
                }
            }
            0 => break true,
            len => len as usize,
        };
        if len > MAX_FRAME || read_by(r, &mut buf[..len], deadline).is_err() {
            break false;
        }
        match !*revoked.lock().unwrap() && valid(&buf[..len], addr) && inj.send(&buf[..len]) {
            true => injected += 1,
            false => dropped += 1,
        }
    };
    // Each refusal is in the tap's count, whatever becomes of the stream: a frame tried again was
    // taken, one never taken is in `dropped` (#1245).
    let refused = inj.refused();
    if !ended {
        return refused;
    }
    let tap_dropped = inj.dropped();
    let reply = json!({"injected": injected, "dropped": dropped + tap_dropped});
    let replied = refused + write_by(&conn, format!("{reply}\n").as_bytes(), deadline).map_or(0, |()| tap_dropped);
    // Reply before closing: even a failed spawn closes inline only after reporting the counts.
    // Closing a packet socket waits for an RCU grace period (tens of ms).
    if let Err(e) = std::thread::Builder::new().name("injector-close".into()).spawn(move || drop(inj)) {
        // A failed spawn drops its closure (and injector) inline.
        crate::log!("injector closed inline: {e}");
    }
    replied
}

/// A whole IPv4 packet for `addr`'s IPv4 address, or a whole IPv6 one of at most `MAX_FRAME` for
/// its IPv6 address that `upper6` takes: all a guest is ever handed.
pub fn valid(p: &[u8], addr: crate::net::VmAddr) -> bool {
    if p.first().is_some_and(|b| b >> 4 == 6) {
        // At most a frame, as an IPv4 packet is by its own length: a longer one would break the stream.
        return addr.v6.is_some_and(|v6| p.len() <= MAX_FRAME && upper6(p).is_some() && p[24..40] == v6.octets());
    }
    let ip = addr.v4;
    let ihl = (p.first().copied().unwrap_or(0) & 15) as usize * 4;
    p.len() >= 20 && p[0] >> 4 == 4 && ihl >= 20 && ihl <= p.len() && u16::from_be_bytes([p[2], p[3]]) as usize == p.len() && p[16..20] == ip.octets()
}

pub fn start(conn: &TcpStream) -> Result<()> {
    let deadline = Instant::now() + ACCEPT_WAIT;
    write_by(conn, &START.to_be_bytes(), deadline)?;
    let mut ack = [0u8; 1];
    By { s: conn, at: deadline }.read_exact(&mut ack)?;
    if ack[0] != b'a' {
        bail!("the target refused the held packets");
    }
    Ok(())
}

/// Before `switch` moves the route, `SYNC`s until the target injected all sent so far. With
/// `handoff` (hosts sharing routes) the target routes the address itself, after those.
pub fn send(holder: &Holder, ip: Ipv4Addr, mig: u64, conn: &TcpStream, handoff: bool, switch: impl FnOnce() -> Result<()>) -> Option<(Stats, Result<()>)> {
    let out = std::cell::RefCell::new(Out { buf: Vec::with_capacity(64 << 10), broken: false, conn });
    let mut sink = |p: &[u8]| out.borrow_mut().frame(p);
    let mut barrier = || {
        let mut o = out.borrow_mut();
        o.buf.extend_from_slice(&SYNC.to_be_bytes());
        let (mut ack, deadline) = ([0u8; 1], Instant::now() + SYNC_WAIT);
        let ok = o.flush(deadline) && By { s: conn, at: deadline }.read_exact(&mut ack).is_ok() && ack[0] == b's';
        if !ok {
            o.broken = true;
            crate::log!("hold {ip}: the target did not confirm the held packets; dropping the rest");
        }
        ok
    };
    // A handoff moves the route on the target; `switch` runs after the stragglers went, as
    // until they are injected, packets routed to the target overtake them.
    let mut switch = Some(switch);
    let handover = || match handoff {
        true => {
            let mut o = out.borrow_mut();
            o.buf.extend_from_slice(&SWITCH.to_be_bytes());
            let (mut ack, deadline) = ([0u8; 1], Instant::now() + SWITCH_WAIT);
            let answered = o.flush(deadline) && By { s: conn, at: deadline }.read_exact(&mut ack).is_ok();
            match ack[0] {
                b'w' if answered => Switch::Switched,
                // It could not route the address yet: the rest still goes to it, which routes
                // the address once the stream ends.
                b'n' if answered => {
                    crate::log!("hold {ip}: the target could not take the address over; it routes it after the held packets");
                    Switch::Refused
                }
                _ => {
                    o.broken = true;
                    crate::log!("hold {ip}: the target did not take the address over; dropping the rest");
                    Switch::Lost(format!("the target did not take {ip} over (its held packets after this are lost)").into())
                }
            }
        }
        false => switch.take().map_or(Ok(()), |f| f()).map_or_else(Switch::Lost, |()| Switch::Switched),
    };
    let (mut stats, switched) = holder.release(ip, mig, &mut sink, &mut barrier, handover)?;
    let mut o = out.into_inner();
    o.buf.extend_from_slice(&0u32.to_be_bytes());
    match o.flush(Instant::now() + FLUSH_WAIT).then(|| read_reply(conn, Instant::now() + REPLY_WAIT)).flatten() {
        Some(r) => (stats.injected, stats.dropped_target) = (r["injected"].as_u64().unwrap_or(0), r["dropped"].as_u64().unwrap_or(0)),
        None => stats.dropped_target = stats.packets,
    }
    // Refused, the target routes the address itself once the stream ends (or breaks): no route
    // is owed here, nor retried (#539).
    let switched = match switched {
        Switch::Refused => Ok(()),
        Switch::Switched => switch.take().map_or(Ok(()), |f| f()),
        Switch::Lost(e) => Err(e),
    };
    Some((stats, switched))
}

/// The final reply on the held-packet stream; its caller reads nothing further.
fn read_reply(conn: &TcpStream, deadline: Instant) -> Option<Value> {
    crate::util::recv_json_max(&mut BufReader::new(By { s: conn, at: deadline }), 257).ok().flatten()
}

struct Out<'a> {
    buf: Vec<u8>,
    broken: bool,
    conn: &'a TcpStream,
}

impl Out<'_> {
    fn frame(&mut self, p: &[u8]) -> bool {
        if self.broken {
            return false;
        }
        self.buf.extend_from_slice(&(p.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(p);
        self.buf.len() < 48 << 10 || self.flush(Instant::now() + FLUSH_WAIT)
    }

    fn flush(&mut self, deadline: Instant) -> bool {
        if !self.broken {
            self.broken = write_by(self.conn, &self.buf, deadline).is_err();
        }
        self.buf.clear();
        !self.broken
    }
}

/// The error flag: a fatal setup error (rather than no TUN support).
fn open_tun(dev: &str) -> std::result::Result<(String, OwnedFd), (bool, crate::util::Error)> {
    let fd = eintr(|| unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK) })
        .map_err(|e| (false, format!("/dev/net/tun: {e}").into()))?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let flags = (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short;
    let dev = crate::net::free_tun(&fd, dev, flags).map_err(|e| {
        let fatal = (e.raw_os_error().is_none() && e.kind() == std::io::ErrorKind::InvalidInput) || matches!(e.raw_os_error(), Some(libc::EPERM));
        (fatal, format!("{dev}: {e}").into())
    })?;
    let mut req = crate::net::ifreq(&dev).map_err(|e| (true, e))?;
    // TUN_F_CSUM: checksums reach us left to the device (`accept`), never completed by the
    // kernel at whatever offset a guest gave.
    const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54d0;
    eintr(|| unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETOFFLOAD as _, 1 as libc::c_ulong) })
        .map_err(|e| (true, format!("{dev}: checksum offload: {e}").into()))?;
    // Room for what arrives while a release catches up (default 500).
    req.ifr_ifru.ifru_metric = TXQ as i32;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock >= 0 {
        let sock = unsafe { OwnedFd::from_raw_fd(sock) };
        unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFTXQLEN as _, &req) };
    }
    Ok((dev, fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hand_over_keeps_the_batch_remainder_ahead_of_new_packets() {
        let (h, _w) = paired();
        for sent in [1, 128, 256] {
            let packets: VecDeque<_> = (0..300).map(|i: usize| vec![i as u8; i + 1]).collect();
            let bytes = packets.iter().map(Vec::len).sum();
            let e = Entry { mig: 1, v6: None, q: Mutex::new(Queue { packets: packets.clone(), bytes, ..Queue::default() }) };
            let (mut stats, mut delivered) = (Stats::default(), Vec::new());
            h.hand_over(
                &e,
                &mut |p| {
                    delivered.push(p.to_vec());
                    if delivered.len() == sent {
                        let mut q = e.q.lock().unwrap();
                        q.packets.push_back(vec![42]);
                        q.bytes += 1;
                        drop(q);
                        std::thread::sleep(CATCH_UP + Duration::from_millis(10));
                    }
                    true
                },
                &mut stats,
            );
            {
                let q = e.q.lock().unwrap();
                let expected: VecDeque<_> = packets.iter().skip(sent).cloned().chain([vec![42]]).collect();
                assert_eq!(q.packets, expected);
                assert_eq!(q.bytes, expected.iter().map(Vec::len).sum::<usize>());
                assert_eq!((stats.packets, stats.dropped, q.dropped), (sent as u64, 0, 0));
            }
            h.give_queued(
                &e,
                &mut |p| {
                    delivered.push(p.to_vec());
                    true
                },
                &mut stats,
            );
            assert_eq!(delivered, packets.into_iter().chain([vec![42]]).collect::<Vec<_>>());
            assert_eq!((stats.packets, stats.bytes, stats.dropped), (301, bytes as u64 + 1, 0));
            assert_eq!(e.q.lock().unwrap().bytes, 0);
        }
    }

    #[test]
    fn stragglers_keep_read_order_while_the_sender_waits() {
        let (mut h, _w) = paired();
        // The send is supplied below; only socket presence is checked when queueing.
        h.resend = Some(h.tun.try_clone().unwrap());
        let ip = Ipv4Addr::new(10, 9, 0, 3);
        h.gone.lock().unwrap().insert(ip, Gone::new(true));
        let (sending, started) = std::sync::mpsc::channel();
        let (queued, pending) = std::sync::mpsc::channel();
        let mut output = Vec::new();
        std::thread::scope(|sc| {
            let (h, output) = (&h, &mut output);
            sc.spawn(move || {
                {
                    let _rx = h.rx.lock().unwrap();
                    assert!(h.straggler(ip, &mut udp_to(ip)));
                }
                h.drain_stragglers(|_, p| {
                    assert!(h.rx.try_lock().is_ok());
                    assert!(h.gone.try_lock().is_ok());
                    assert!(h.stragglers.try_lock().is_ok());
                    if output.is_empty() {
                        sending.send(()).unwrap();
                        pending.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    output.push(p[28]);
                    true
                });
            });
            sc.spawn(move || {
                started.recv_timeout(Duration::from_secs(5)).unwrap();
                for i in 1..=128 {
                    let _rx = h.rx.lock().unwrap();
                    let mut p = udp_to(ip);
                    p[28] = i;
                    assert!(!h.straggler(ip, &mut p), "the first reader still owns the drain");
                }
                queued.send(()).unwrap();
            });
        });
        assert_eq!(output, (0..=128).collect::<Vec<_>>());
        assert_eq!(h.gone.lock().unwrap()[&ip].resent, 129);
        assert!(!h.stragglers.lock().unwrap().draining);
        // An empty drain hands ownership back; a later reader starts it again.
        {
            let _rx = h.rx.lock().unwrap();
            assert!(h.straggler(ip, &mut udp_to(ip)));
        }
        h.drain_stragglers(|_, _| false);
        assert_eq!(h.gone.lock().unwrap()[&ip].dropped, 1);
    }

    #[test]
    fn stragglers_beyond_the_cap_are_counted_as_dropped() {
        let (mut h, _w) = paired();
        h.resend = Some(h.tun.try_clone().unwrap());
        let ip = Ipv4Addr::new(10, 9, 0, 3);
        h.gone.lock().unwrap().insert(ip, Gone::new(true));
        let size = udp_to(ip).len();
        let fit = CAP / size;
        let _rx = h.rx.lock().unwrap();
        assert!(h.straggler(ip, &mut udp_to(ip)), "the first reader owns the drain");
        for _ in 1..fit + 3 {
            assert!(!h.straggler(ip, &mut udp_to(ip)));
        }
        drop(_rx);
        assert_eq!(h.stragglers.lock().unwrap().bytes, fit * size);
        assert_eq!(h.gone.lock().unwrap()[&ip].dropped, 3);
        let mut sent = 0;
        h.drain_stragglers(|_, _| {
            sent += 1;
            true
        });
        assert_eq!((sent, h.stragglers.lock().unwrap().bytes), (fit, 0));
        assert_eq!(h.gone.lock().unwrap()[&ip].resent, fit as u64);
    }

    #[test]
    fn queued_stragglers_keep_their_counts_after_rehold_or_expiry() {
        let (mut h, _w) = paired();
        h.resend = Some(h.tun.try_clone().unwrap());
        let ip = Ipv4Addr::new(10, 9, 0, 3);
        for replaced in [false, true] {
            for sent in [false, true] {
                let old = Gone { at: Instant::now() - Duration::from_secs(1), ..Gone::new(true) };
                h.gone.lock().unwrap().insert(ip, old);
                assert!(h.straggler(ip, &mut udp_to(ip)));
                let (_, count, _) = h.stragglers.lock().unwrap().packets.pop_front().unwrap();
                assert_eq!((count.resent, count.dropped), (1, 0), "queued packet carries its count");
                if replaced {
                    h.gone.lock().unwrap().insert(ip, Gone::new(true));
                } else {
                    h.gone.lock().unwrap().get_mut(&ip).unwrap().at -= GONE_FOR;
                    h.report_stragglers();
                    assert!(!h.gone.lock().unwrap().contains_key(&ip));
                }
                let report = h.count_straggler(ip, count, sent).expect("the removed record's count must still be reported");
                assert_eq!((report.resent, report.dropped), (u64::from(sent), u64::from(!sent)));
                assert_eq!(report.at, old.at);
                if replaced {
                    let g = h.gone.lock().unwrap()[&ip];
                    assert_eq!((g.resent, g.dropped), (0, 0), "a new release has its own counts");
                }
                h.drain_stragglers(|_, _| panic!("already drained"));
            }
        }
    }

    #[test]
    fn concurrent_stragglers_match_read_order() {
        let (mut h, _w) = paired();
        h.resend = Some(h.tun.try_clone().unwrap());
        let ip = Ipv4Addr::new(10, 9, 0, 3);
        h.gone.lock().unwrap().insert(ip, Gone::new(true));
        let (read, output) = (Mutex::new(Vec::new()), Mutex::new(Vec::new()));
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|sc| {
            for t in 0..2u16 {
                let (h, read, output, start) = (&h, &read, &output, &start);
                sc.spawn(move || {
                    start.wait();
                    for i in 0..256u16 {
                        let id = t * 256 + i;
                        let drain = {
                            let _rx = h.rx.lock().unwrap();
                            read.lock().unwrap().push(id);
                            let mut p = udp_to(ip);
                            p[4..6].copy_from_slice(&id.to_be_bytes());
                            h.straggler(ip, &mut p)
                        };
                        std::thread::yield_now();
                        if drain {
                            h.drain_stragglers(|_, p| {
                                output.lock().unwrap().push(u16::from_be_bytes([p[4], p[5]]));
                                std::thread::yield_now();
                                true
                            });
                        }
                    }
                });
            }
        });
        assert_eq!(*output.lock().unwrap(), *read.lock().unwrap());
        assert_eq!(h.gone.lock().unwrap()[&ip].resent, 512);
    }

    /// #1245: a full tap is waited for only while its guest runs, takes frames within
    /// `TAP_STALL` and the waits stay within `TAP_BUDGET`; once not, never again for that
    /// injector, however its guest goes on.
    #[test]
    fn a_full_tap_is_waited_for_within_bounds() {
        assert!(!Wait::new(false).again(), "a paused guest is never waited for");
        let mut w = Wait::new(true);
        assert!(w.again(), "a running guest is");
        w.took -= TAP_STALL;
        assert!(!w.again(), "stalled");
        w.took = Instant::now();
        assert!(!w.again(), "stalled once, never waited for again");
        let mut w = Wait::new(true);
        w.waited = TAP_BUDGET - Duration::from_millis(1);
        assert!(w.again(), "within the budget");
        w.waited = TAP_BUDGET;
        assert!(!w.again(), "the budget spent");
        w.waited = Duration::ZERO;
        assert!(!w.again(), "spent once, never waited for again");
    }

    #[test]
    fn injector_sends_header_and_payload_in_order() {
        // An established TCP socket ignores the destination address; no raw socket privilege needed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let injector = Injector {
            fd: stream.into(),
            tap: String::new(),
            ifindex: 0,
            header: [7; 12],
            tx_dropped: 0,
            refused: AtomicU64::new(0),
            wait: Mutex::new(Wait::new(false)),
        };
        // Each frame's ethertype is its packet's: IPv6 by its version, anything else IPv4.
        let v6 = udp6_to(V6);
        for (packet, ethertype) in
            [(b"".as_slice(), [8, 0]), (b"payload", [8, 0]), (&[42; 1500], [8, 0]), (&udp_to(Ipv4Addr::new(10, 9, 0, 8)), [8, 0]), (&v6, [0x86, 0xdd])]
        {
            assert!(injector.send(packet));
            let mut frame = vec![0; 14 + packet.len()];
            peer.read_exact(&mut frame).unwrap();
            assert_eq!((&frame[..12], &frame[12..14]), (&injector.header[..], &ethertype[..]));
            assert_eq!(&frame[14..], packet);
        }
    }

    /// Reading `tun`, with no routes or raw socket: nothing here needs root.
    fn holder(tun: OwnedFd) -> Holder {
        let (held, gone) = (Mutex::default(), Mutex::default());
        Holder {
            dev: "test".into(),
            ifindex: 0,
            tun,
            held,
            reading: AtomicBool::new(false),
            routes: Mutex::new(()),
            ipv6: AtomicBool::new(false),
            rx: Mutex::new(()),
            gone,
            stragglers: Mutex::default(),
            resend: None,
            resend6: None,
            no_resend6: None,
        }
    }

    /// A holder reading a datagram socket standing in for its tun (the kernel's reads: one frame each), and the
    /// socket's other end, to write frames to.
    fn paired() -> (Holder, OwnedFd) {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
        unsafe { (holder(OwnedFd::from_raw_fd(fds[0])), OwnedFd::from_raw_fd(fds[1])) }
    }

    /// A UDP datagram 10.9.0.2 -> `dst` (ports 12345 -> 54321), its header checksum filled in.
    fn udp_to(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 29, 0, 1, 0, 0, 64, 17, 0, 0, 10, 9, 0, 2, 0, 0, 0, 0, 0x30, 0x39, 0xd4, 0x31, 0, 9, 0, 0, 0];
        p[16..20].copy_from_slice(&dst.octets());
        let sum = !sum16(&p[..20]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p
    }

    /// The IPv6 address of a held VM in the tests (10.9.0.8 under fd00:7::/96).
    const V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 7, 0, 0, 0, 0, 0x0a09, 8);

    /// `udp_to` over IPv6: 2001:db8::2 -> `dst`, its checksum unset.
    fn udp6_to(dst: Ipv6Addr) -> Vec<u8> {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        [&[0x60, 0, 0, 0, 0, 9, 17, 64][..], &src.octets(), &dst.octets(), &[0x30, 0x39, 0xd4, 0x31, 0, 9, 0, 0, 0]].concat()
    }

    /// The sum of an IPv6 packet's pseudo-header and its upper-layer packet: 0xffff if the
    /// latter's checksum verifies.
    fn sum6(p: &[u8]) -> u16 {
        let len = (p.len() as u32 - 40).to_be_bytes();
        sum16(&[&p[8..40], &len, &[0, 0, 0, p[6]], &p[40..]].concat())
    }

    /// `p` as a tap frame: virtio-net header (`flags`, `gso_type`, csum start and offset from
    /// the Ethernet header), Ethernet header (IPv4), and `pad` bytes after it.
    fn tap_frame(p: &[u8], flags: u8, gso: u8, csum: (u16, u16), pad: usize) -> Vec<u8> {
        tap_frame_of([8, 0], p, flags, gso, csum, pad)
    }

    /// `tap_frame` with an IPv6 Ethernet header.
    fn tap_frame6(p: &[u8], flags: u8, gso: u8, csum: (u16, u16), pad: usize) -> Vec<u8> {
        tap_frame_of([0x86, 0xdd], p, flags, gso, csum, pad)
    }

    fn tap_frame_of(ethertype: [u8; 2], p: &[u8], flags: u8, gso: u8, csum: (u16, u16), pad: usize) -> Vec<u8> {
        [&vnet_hdr(flags, gso, csum)[..], &[0, 0], &[2; 12], &ethertype, p, &vec![0; pad]].concat()
    }

    /// A struct virtio_net_hdr: `flags`, `gso_type`, csum start and offset.
    fn vnet_hdr(flags: u8, gso: u8, csum: (u16, u16)) -> Vec<u8> {
        [&[flags, gso, 0, 0, 0, 0][..], &csum.0.to_le_bytes(), &csum.1.to_le_bytes()].concat()
    }

    /// Codex's #406 frame: a UDP datagram from 10.0.0.2 whose payload makes a completion over
    /// bytes 13 on write 0xffff at bytes 13-14, its source then 10.255.255.2.
    fn forgery() -> Vec<u8> {
        let mut p = [&udp_to(Ipv4Addr::new(10, 9, 0, 8))[..], &[0, 0]].concat();
        (p[3], p[25]) = (31, 11);
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[10..12].fill(0);
        let sum = !sum16(&p[..20]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        let x = (0..=u16::MAX).find(|&x| {
            p[29..31].copy_from_slice(&x.to_be_bytes());
            sum16(&p[13..]) == 0xffff
        });
        assert!(x.is_some());
        p
    }

    #[test]
    fn completion_never_writes_into_the_ip_header() {
        let p = forgery();
        // Completed as asked, the source is forged and the header checksum still passes.
        let mut naive = p.clone();
        let sum = !sum16(&p[13..]);
        naive[13..15].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
        assert_eq!((&naive[12..16], ipv4_header_csum_ok(&naive)), (&[10, 255, 255, 2][..], true));
        assert_eq!(cut(&tap_frame(&p, 1, 0, (14 + 13, 0), 0)), None, "Codex's frame");
        assert_eq!(cut(&tap_frame(&p, 1, 0, (14 + 21, 6), 0)), None, "a misaligned start");
        assert_eq!(cut(&tap_frame(&p, 1, 0, (14 + 20, 16), 0)), None, "TCP's field in a UDP packet");
        assert!(cut(&tap_frame(&p, 1, 0, (14 + 20, 6), 0)).is_some(), "UDP's own field");
        // The hold device's reads too: the kernel leaves completion to it.
        let (h, w) = paired();
        let dst = Ipv4Addr::new(10, 9, 0, 8);
        h.held.lock().unwrap().insert(dst, Arc::new(Entry { mig: 1, v6: None, q: Mutex::default() }));
        let mut buf = vec![0u8; VNET_HDR + MAX_FRAME];
        for (csum, queued) in [((13, 0), 0), ((21, 6), 0), ((20, 16), 0), ((20, 6), 1)] {
            let f = [&vnet_hdr(1, 0, csum)[..], &p].concat();
            assert_eq!(unsafe { libc::write(w.as_raw_fd(), f.as_ptr().cast(), f.len()) }, f.len() as isize);
            h.read_one(&mut buf);
            assert_eq!(h.entry(dst).unwrap().q.lock().unwrap().packets.len(), queued, "{csum:?}");
        }
        let q = h.entry(dst).unwrap().q.lock().unwrap().packets[0].clone();
        assert_eq!((&q[12..16], ipv4_header_csum_ok(&q)), (&[10, 0, 0, 2][..], true));
    }

    #[test]
    fn tap_frames_become_packets_with_their_checksums_completed() {
        // As the host sends to a tap with checksum offload: the UDP checksum holds the pseudo-header's sum.
        let mut p = udp_to(Ipv4Addr::new(10, 9, 0, 8));
        let pseudo = [&p[12..20], &[0, 17, 0, 9]].concat();
        p[26..28].copy_from_slice(&sum16(&pseudo).to_be_bytes());
        let got = cut(&tap_frame(&p, 1, 0, (14 + 20, 6), 3)).unwrap().remove(0);
        assert_eq!(got.len(), 29, "Ethernet padding is not the packet's");
        assert_eq!((&got[..26], &got[28..]), (&p[..26], &p[28..]));
        assert_eq!(sum16(&[&pseudo[..], &got[20..]].concat()), 0xffff, "the UDP checksum verifies");
        assert_eq!(cut(&tap_frame(&p, 0, 0, (0, 0), 0)).unwrap(), [p.clone()], "a complete one is as it was");
        assert_eq!(cut(&tap_frame(&p, 1, 3, (14 + 20, 6), 0)), None, "UDP GSO");
        let mut arp = tap_frame(&p, 0, 0, (0, 0), 0);
        arp[24..26].copy_from_slice(&[8, 6]);
        assert_eq!(cut(&arp), None, "not IPv4");
        assert_eq!(cut(&tap_frame(&p[..20], 0, 0, (0, 0), 0)), None, "truncated");
    }

    /// `from_tap` with all of `CAP` to fill.
    fn cut(f: &[u8]) -> Option<Vec<Vec<u8>>> {
        from_tap(f, CAP).map(|r| r.unwrap())
    }

    /// `frames` handed to `hold_first`, as `Vm::take_tap_queue` would.
    fn feed(frames: &[Vec<u8>]) -> impl FnOnce(Each) + '_ {
        move |each| frames.iter().for_each(|f| each(f))
    }

    /// As the host's TCP sends `data` to a tap with TSO, cut by `mss`: one frame, its checksum
    /// field holding the pseudo-header's sum without the length, FIN and PSH set.
    fn tso_frame(data: &[u8], mss: u16, csum: (u16, u16)) -> Vec<u8> {
        let tcp = [&[0x30, 0x39, 0x1f, 0x40][..], &1000u32.to_be_bytes(), &[0, 0, 0, 1], &[0x50, 0x19, 0xff, 0xff, 0, 0, 0, 0]].concat();
        let mut p = [&[0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0, 10, 9, 0, 2, 10, 9, 0, 8][..], &tcp, data].concat();
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        let sum = !sum16(&p[..20]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        let pseudo = sum16(&[&p[12..20], &[0, 6, 0, 0]].concat());
        p[36..38].copy_from_slice(&pseudo.to_be_bytes());
        let mut f = tap_frame(&p, 1, 1, csum, 0);
        f[2..4].copy_from_slice(&54u16.to_le_bytes());
        f[4..6].copy_from_slice(&mss.to_le_bytes());
        f
    }

    /// A full tap backlog (`TAP_QUEUE` frames, 64 MB) of TSO frames: one with a tiny
    /// `gso_size` is dropped whole, and others are cut only within `CAP`, the rest counted as
    /// dropped (#415: 64 KiB by 1 byte would be 65,000 packets, gigabytes for a backlog).
    #[test]
    fn a_tap_backlog_takes_at_most_cap() {
        let ip = Ipv4Addr::new(10, 9, 0, 8);
        let data = vec![7u8; 16000];
        let backlog = |h: &Holder, mss: u16| {
            h.held.lock().unwrap().insert(ip, Arc::new(Entry { mig: 1, v6: None, q: Mutex::default() }));
            let f = tso_frame(&data, mss, (14 + 20, 16));
            h.hold_first(ip, 1, |each| (0..crate::net::TAP_QUEUE).for_each(|_| each(&f)));
            let e = h.entry(ip).unwrap();
            let q = e.q.lock().unwrap();
            (q.packets.len() as u64, q.bytes, q.dropped)
        };
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        assert_eq!(backlog(&h, 1), (0, 0, u64::from(crate::net::TAP_QUEUE)), "under MIN_MSS: dropped, nothing made");
        let (kept, bytes, dropped) = backlog(&h, MIN_MSS as u16);
        let per = data.len().div_ceil(MIN_MSS) as u64;
        assert!(bytes <= CAP && kept > 0, "{bytes} bytes in {kept} packets");
        assert_eq!(kept + dropped, per * u64::from(crate::net::TAP_QUEUE), "every segment kept or counted");
    }

    #[test]
    fn a_tso_frame_is_cut_into_its_segments() {
        // As the host's TCP sends to a tap with TSO: one frame for three segments, its checksum
        // field holding the pseudo-header's sum without the length, FIN and PSH set.
        let data: Vec<u8> = (0..3500u32).map(|i| i as u8).collect();
        let tso = |csum: (u16, u16)| tso_frame(&data, 1448, csum);
        let segs = cut(&tso((14 + 20, 16))).unwrap();
        assert_eq!(segs.iter().map(Vec::len).collect::<Vec<_>>(), [40 + 1448, 40 + 1448, 40 + 604]);
        let mut joined = Vec::new();
        for (i, s) in segs.iter().enumerate() {
            assert!(ipv4_header_csum_ok(s) && valid(s, Ipv4Addr::new(10, 9, 0, 8).into()), "segment {i}");
            assert_eq!((&s[12..16], u16::from_be_bytes([s[4], s[5]])), (&[10, 9, 0, 2][..], 0x1234 + i as u16));
            assert_eq!(u32::from_be_bytes(s[24..28].try_into().unwrap()), 1000 + 1448 * i as u32);
            assert_eq!(s[33], if i == 2 { 0x19 } else { 0x10 }, "FIN and PSH on the last only");
            let pseudo = [&s[12..20], &[0, 6], &(s.len() as u16 - 20).to_be_bytes()].concat();
            assert_eq!(sum16(&[&pseudo[..], &s[20..]].concat()), 0xffff, "segment {i}'s TCP checksum verifies");
            joined.extend_from_slice(&s[40..]);
        }
        assert_eq!(joined, data);
        // Held first, in their order, ahead of what was held.
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        let q = Queue { packets: VecDeque::from([b"held".to_vec()]), bytes: 4, ..Queue::default() };
        h.held.lock().unwrap().insert(Ipv4Addr::new(10, 9, 0, 8), Arc::new(Entry { mig: 1, v6: None, q: Mutex::new(q) }));
        h.hold_first(Ipv4Addr::new(10, 9, 0, 8), 1, feed(&[tso((14 + 20, 16))]));
        assert_eq!(h.entry(Ipv4Addr::new(10, 9, 0, 8)).unwrap().q.lock().unwrap().packets, [&segs[..], &[b"held".to_vec()]].concat());
        // Its checksum asked for anywhere but TCP's own field, as for one packet: dropped.
        assert_eq!(cut(&tso((14 + 13, 0))), None, "Codex's offsets");
        assert_eq!(cut(&tso((14 + 20, 6))), None, "UDP's field");
    }

    #[test]
    fn frames_left_on_the_tap_go_ahead_of_the_held_packets() {
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        let ip = Ipv4Addr::new(10, 9, 0, 8);
        let (first, second, held) = (udp_to(ip), [&udp_to(ip)[..28], b"!"].concat(), b"held".to_vec());
        let q = Queue { packets: VecDeque::from([held.clone()]), bytes: 4, ..Queue::default() };
        h.held.lock().unwrap().insert(ip, Arc::new(Entry { mig: 1, v6: None, q: Mutex::new(q) }));
        let frames = [tap_frame(&first, 0, 0, (0, 0), 0), tap_frame(&second, 0, 1, (0, 0), 0), tap_frame(&second, 0, 0, (0, 0), 0)];
        h.hold_first(ip, 2, feed(&frames));
        assert_eq!(h.entry(ip).unwrap().q.lock().unwrap().packets.len(), 1, "another migration's hold");
        h.hold_first(ip, 1, feed(&frames));
        let e = h.entry(ip).unwrap();
        let q = e.q.lock().unwrap();
        assert_eq!(q.packets, [first, second, held]);
        assert_eq!((q.bytes, q.dropped), (29 + 29 + 4, 1), "the GSO frame is counted as dropped");
    }

    #[test]
    fn reader_errors_are_never_read_through_and_stay_logged() {
        for events in [libc::POLLERR, libc::POLLHUP, libc::POLLNVAL, libc::POLLERR | libc::POLLIN] {
            assert!(poll_ready(events).is_err());
        }
        assert!(poll_ready(libc::POLLIN).unwrap());
        assert!(!poll_ready(0).unwrap());
        let mut errors = ReadErrors::default();
        let e = std::io::Error::from_raw_os_error(libc::EIO);
        assert!(errors.failed(&e).unwrap().contains("retrying"));
        assert!(errors.failed(&e).is_none(), "repeats are rate limited");
        // A persistent error is logged again, with its count.
        errors.logged = Some(Instant::now() - READ_ERROR_LOG);
        assert!(errors.failed(&e).unwrap().contains("still failing (3 errors)"));
        assert_eq!(errors.recovered().unwrap(), "reading again after 3 errors");
        assert!(errors.recovered().is_none());
        assert!(errors.failed(&e).unwrap().ends_with("; retrying"), "a new error after recovering is logged at once");
    }

    #[test]
    fn failed_release_and_forget_count_late_drops_once() {
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        let ip = Ipv4Addr::new(10, 100, 254, 9);
        let e = Arc::new(Entry { mig: 1, v6: None, q: Mutex::new(Queue { dropped: 2, ..Queue::default() }) });
        h.held.lock().unwrap().insert(ip, e.clone());
        let (mut stats, result) = h.release_local(ip, 1, &mut |_| true, || Err("route failed".into()), Duration::ZERO).unwrap();
        assert!(result.is_err());
        assert_eq!(stats.dropped, 2);
        // The reader can enqueue between release_local and the caller's forget.
        {
            let mut q = e.q.lock().unwrap();
            q.packets.push_back(vec![0; 20]);
            q.bytes = 20;
            q.dropped = 3;
        }
        stats.dropped += h.forget(ip, 1).dropped;
        assert_eq!(stats.dropped, 6);
        assert_eq!(h.forget(ip, 1).dropped, 0);
    }

    #[test]
    fn duplicate_hold_preserves_queue_and_owner() {
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        let ip = Ipv4Addr::new(10, 100, 254, 9);
        let e =
            Arc::new(Entry { mig: 1, v6: None, q: Mutex::new(Queue { packets: VecDeque::from([vec![0; 20]]), bytes: 20, dropped: 4, ..Queue::default() }) });
        h.held.lock().unwrap().insert(ip, e.clone());
        for mig in [1, 2] {
            assert!(h.hold(ip.into(), mig).unwrap_err().to_string().contains("already holding"));
            assert!(Arc::ptr_eq(&h.entry(ip).unwrap(), &e));
            let q = e.q.lock().unwrap();
            assert_eq!((q.packets.len(), q.bytes, q.dropped), (1, 20, 4));
        }
    }

    #[test]
    fn failed_hold_counts_queued_and_overflow_packets() {
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        let ip = Ipv4Addr::new(10, 100, 254, 9);
        for existing in [false, true] {
            if existing {
                h.gone.lock().unwrap().insert(ip, Gone { resent: 2, dropped: 3, ..Gone::new(true) });
            }
            let e = Arc::new(Entry {
                mig: 1,
                v6: None,
                q: Mutex::new(Queue { packets: VecDeque::from([vec![0; 20], vec![0; 20]]), bytes: 40, dropped: 4, ..Queue::default() }),
            });
            h.held.lock().unwrap().insert(ip, e.clone());
            let _routes = h.routes.lock().unwrap();
            h.discard_hold(ip);
            assert!(h.entry(ip).is_none());
            let g = h.gone.lock().unwrap()[&ip];
            assert_eq!((g.resent, g.dropped), if existing { (2, 9) } else { (0, 6) });
            assert_eq!(g.moved, existing);
            let mut q = e.q.lock().unwrap();
            assert!(q.packets.is_empty());
            assert_eq!(q.bytes, 0);
            assert_eq!(q.discard(), 0);
            h.discard_hold(ip);
            assert_eq!(h.gone.lock().unwrap()[&ip].dropped, g.dropped);
        }
    }

    #[test]
    fn a_rewritten_header_fails_its_checksum() {
        let p = udp_to(Ipv4Addr::new(10, 9, 0, 8));
        assert!(ipv4_header_csum_ok(&p), "a well-formed header passes");
        // Checksum completion overwrote the low two bytes of the source (#362): the header
        // checksum is now stale, so it no longer verifies.
        let mut forged = p.clone();
        forged[14] = 0x00;
        forged[15] = 0x63;
        assert!(!ipv4_header_csum_ok(&forged), "a rewritten source no longer matches the checksum");
        assert!(!ipv4_header_csum_ok(&p[..19]), "a truncated header is rejected");
    }

    #[test]
    fn read_one_drops_a_rewritten_header() {
        // A held entry for the destination, and the reader fed from a pipe standing in for the tun.
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        let h = holder(unsafe { OwnedFd::from_raw_fd(r) });
        let dst = Ipv4Addr::new(10, 9, 0, 8);
        h.held.lock().unwrap().insert(dst, Arc::new(Entry { mig: 1, v6: None, q: Mutex::default() }));
        let p = udp_to(dst);
        let queued = || h.entry(dst).unwrap().q.lock().unwrap().packets.len();
        let write = |p: &[u8]| {
            let f = [&vnet_hdr(0, 0, (0, 0))[..], p].concat();
            assert_eq!(unsafe { libc::write(w, f.as_ptr().cast(), f.len()) }, f.len() as isize)
        };
        let mut buf = vec![0u8; 2048];
        write(&p);
        h.read_one(&mut buf);
        assert_eq!(queued(), 1, "a valid packet is queued");
        // Checksum completion overwrote the source low byte (#362): now dropped, not queued or straggled.
        let mut forged = p.clone();
        forged[15] ^= 0xff;
        write(&forged);
        h.read_one(&mut buf);
        assert_eq!(queued(), 1, "a rewritten-header packet is dropped");
        assert_eq!(h.entry(dst).unwrap().q.lock().unwrap().dropped, 1, "and counted for its address (#512)");
        // Let go of, the address counts it with its stragglers.
        h.held.lock().unwrap().clear();
        h.gone.lock().unwrap().insert(dst, Gone::new(false));
        write(&forged);
        h.read_one(&mut buf);
        assert_eq!(h.gone.lock().unwrap()[&dst].dropped, 1, "a let-go address counts it too");
        unsafe { libc::close(w) };
    }

    /// IPv6 to a held /128 (`vm_ipv6_prefix`) is held for its IPv4 address, the low 32 bits of its
    /// destination, with its checksum completed as an IPv4 one's is. Never queued, re-sent or
    /// counted for another /128 with those low bits, nor for whatever its source's bytes read as;
    /// the host's multicast is passed by. One `accept6` refuses is counted as dropped.
    #[test]
    fn ipv6_to_a_held_address_is_held_for_it() {
        let (h, w) = paired();
        let (dst, decoy) = (Ipv4Addr::new(10, 9, 0, 8), Ipv4Addr::new(0, 0, 0, 1));
        h.held.lock().unwrap().insert(dst, Arc::new(Entry { mig: 1, v6: Some(V6), q: Mutex::default() }));
        h.held.lock().unwrap().insert(decoy, Arc::new(Entry { mig: 1, v6: Some("fd00:7::1".parse().unwrap()), q: Mutex::default() }));
        let ipv6 = |src: &str, to: &str| {
            let (src, to) = (src.parse::<Ipv6Addr>().unwrap(), to.parse::<Ipv6Addr>().unwrap());
            [&[0x60, 0, 0, 0, 0, 8, 17, 64][..], &src.octets(), &to.octets(), &[0; 8]].concat()
        };
        let mut buf = vec![0u8; 2048];
        let mut write = |flags: u8, gso: u8, csum: (u16, u16), p: &[u8]| {
            let f = [&vnet_hdr(flags, gso, csum)[..], p].concat();
            assert_eq!(unsafe { libc::write(w.as_raw_fd(), f.as_ptr().cast(), f.len()) }, f.len() as isize);
            h.read_one(&mut buf);
        };
        let q = |ip| {
            let e = h.entry(ip).unwrap();
            let q = e.q.lock().unwrap();
            (q.packets.clone(), q.dropped)
        };
        // Its source's bytes 8..12 (where an IPv4 destination would be) read as `decoy`.
        let held = ipv6("2001:db8:0:1:0:0:0:1", "fd00:7::a09:8");
        write(0, 0, (0, 0), &held);
        // Another prefix's address with the same low 32 bits, and the host's multicast: no one's.
        write(0, 0, (0, 0), &ipv6("2001:db8::2", "fd00:8::a09:8"));
        write(0, 0, (0, 0), &ipv6("fe80::1", "ff02::16"));
        assert_eq!((q(dst), q(decoy)), ((VecDeque::from([held.clone()]), 0), (VecDeque::new(), 0)));
        // Its UDP checksum left to the device: completed in UDP's own field only, 40 bytes in.
        let mut p = udp6_to(V6);
        let pseudo = sum16(&[&p[8..40], &[0, 0, 0, 9, 0, 0, 0, 17]].concat());
        p[46..48].copy_from_slice(&pseudo.to_be_bytes());
        for csum in [(20, 6), (41, 6), (40, 16), (24, 0)] {
            write(1, 0, csum, &p);
        }
        assert_eq!(q(dst).1, 4, "completion anywhere but UDP's field is refused");
        write(1, 0, (40, 6), &p);
        let got = q(dst).0.pop_back().unwrap();
        assert_eq!((&got[..46], &got[48..], sum6(&got)), (&p[..46], &p[48..], 0xffff), "the UDP checksum verifies");
        // Refused, and counted for it: an extension header (hop-by-hop, here), ICMPv6 left to the
        // device, neighbour discovery, a payload length that is not all of it, GSO.
        let mut hop = udp6_to(V6);
        hop[6] = 0;
        let mut icmp = udp6_to(V6);
        (icmp[6], icmp[40]) = (58, 128);
        let mut nd = icmp.clone();
        nd[40] = 135;
        let mut short = udp6_to(V6);
        short[5] = 8;
        let before = q(dst);
        for (flags, gso, csum, p) in [(0, 0, (0, 0), &hop), (1, 0, (40, 2), &icmp), (0, 0, (0, 0), &nd), (0, 0, (0, 0), &short), (0, 4, (0, 0), &p)] {
            write(flags, gso, csum, p);
        }
        assert_eq!(q(dst), (before.0.clone(), before.1 + 5));
        write(0, 0, (0, 0), &icmp);
        assert_eq!(q(dst).0.len(), before.0.len() + 1, "an echo request is held");
        // Without an IPv6 address the hold takes none.
        h.held.lock().unwrap().insert(dst, Arc::new(Entry { mig: 2, v6: None, q: Mutex::default() }));
        write(0, 0, (0, 0), &held);
        assert_eq!(q(dst), (VecDeque::new(), 0));
    }

    #[test]
    fn only_whole_packets_for_the_vm_are_valid() {
        let (v4, other) = (Ipv4Addr::new(10, 9, 0, 8), Ipv4Addr::new(10, 9, 0, 9));
        let both = crate::net::VmAddr { v4, v6: Some(V6) };
        // IPv4 as before, whether or not it has an IPv6 address.
        for addr in [v4.into(), both] {
            assert!(valid(&udp_to(v4), addr) && !valid(&udp_to(other), addr) && !valid(&udp_to(v4)[..28], addr));
        }
        let p = udp6_to(V6);
        assert!(valid(&p, both));
        assert!(!valid(&p, v4.into()), "no IPv6 address: none");
        assert!(!valid(&p, crate::net::VmAddr { v4, v6: Some("fd00:8::a09:8".parse().unwrap()) }), "another's");
        assert!(!valid(&p[..48], both) && !valid(&[&p[..], &[0]].concat(), both), "not its payload length");
        assert!(!valid(&p[..39], both), "truncated");
        let mut big = [&p[..], &vec![0; MAX_FRAME - p.len()]].concat();
        big[4..6].copy_from_slice(&((MAX_FRAME - 40) as u16).to_be_bytes());
        assert!(valid(&big, both), "a frame's worth");
        big.push(0);
        big[4..6].copy_from_slice(&((MAX_FRAME - 39) as u16).to_be_bytes());
        assert!(!valid(&big, both) && cut(&tap_frame6(&big, 0, 0, (0, 0), 0)).is_none(), "more than a frame");
        for (next, ok) in [(6, true), (17, true), (0, false), (43, false), (44, false), (60, false), (50, false), (59, false)] {
            let mut q = p.clone();
            q[6] = next;
            assert_eq!(valid(&q, both), ok, "next header {next}");
        }
        for (kind, ok) in [(128, true), (129, true), (1, true), (2, true), (133, false), (134, false), (135, false), (136, false), (137, false)] {
            let mut q = p.clone();
            (q[6], q[40]) = (58, kind);
            assert_eq!(valid(&q, both), ok, "ICMPv6 type {kind}");
        }
    }

    #[test]
    fn ipv6_tap_frames_become_packets() {
        let mut p = udp6_to(V6);
        let pseudo = sum16(&[&p[8..40], &[0, 0, 0, 9, 0, 0, 0, 17]].concat());
        p[46..48].copy_from_slice(&pseudo.to_be_bytes());
        let got = cut(&tap_frame6(&p, 1, 0, (14 + 40, 6), 3)).unwrap().remove(0);
        assert_eq!((got.len(), sum6(&got)), (49, 0xffff), "padding left off, its UDP checksum completed");
        assert_eq!(cut(&tap_frame6(&p, 0, 0, (0, 0), 0)).unwrap(), [p.clone()], "a complete one is as it was");
        assert_eq!(cut(&tap_frame6(&p, 1, 0, (14 + 20, 6), 0)), None, "IPv4's offset");
        assert_eq!(cut(&tap_frame6(&p, 1, 0, (14 + 40, 16), 0)), None, "TCP's field in a UDP packet");
        assert_eq!(cut(&tap_frame6(&p, 1, 5, (14 + 40, 6), 0)), None, "UDP GSO");
        assert_eq!(cut(&tap_frame6(&p[..40], 0, 0, (0, 0), 0)), None, "truncated");
        // Its ethertype and version must agree.
        assert_eq!(cut(&tap_frame(&p, 0, 0, (0, 0), 0)), None, "IPv6 in an IPv4 frame");
        assert_eq!(cut(&tap_frame6(&udp_to(Ipv4Addr::new(10, 9, 0, 8)), 0, 0, (0, 0), 0)), None, "IPv4 in an IPv6 frame");
        let mut hop = p.clone();
        hop[6] = 0;
        assert_eq!(cut(&tap_frame6(&hop, 0, 0, (0, 0), 0)), None, "an extension header");
    }

    /// `tso_frame` over IPv6 (gso_type 4), 2001:db8::2 -> `V6`, with CWR and ECE set too.
    fn tso6_frame(data: &[u8], mss: u16, csum: (u16, u16)) -> Vec<u8> {
        let tcp = [&[0x30, 0x39, 0x1f, 0x40][..], &1000u32.to_be_bytes(), &[0, 0, 0, 1], &[0x50, 0xd9, 0xff, 0xff, 0, 0, 0, 0]].concat();
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let mut p = [&[0x60, 0, 0, 0, 0, 0, 6, 64][..], &src.octets(), &V6.octets(), &tcp, data].concat();
        let len = (p.len() - 40) as u16;
        p[4..6].copy_from_slice(&len.to_be_bytes());
        // As `tcp_v6_gso_csum_prep` leaves it: the pseudo-header's sum with a length of 0.
        let pseudo = sum16(&[&p[8..40], &[0, 0, 0, 0, 0, 0, 0, 6]].concat());
        p[56..58].copy_from_slice(&pseudo.to_be_bytes());
        let mut f = tap_frame6(&p, 1, 4, csum, 0);
        f[2..4].copy_from_slice(&74u16.to_le_bytes());
        f[4..6].copy_from_slice(&mss.to_le_bytes());
        f
    }

    #[test]
    fn a_tcpv6_tso_frame_is_cut_into_its_segments() {
        let data: Vec<u8> = (0..3500u32).map(|i| i as u8).collect();
        let tso = |csum: (u16, u16)| tso6_frame(&data, 1428, csum);
        let segs = cut(&tso((14 + 40, 16))).unwrap();
        assert_eq!(segs.iter().map(Vec::len).collect::<Vec<_>>(), [60 + 1428, 60 + 1428, 60 + 644]);
        let mut joined = Vec::new();
        let both = crate::net::VmAddr { v4: Ipv4Addr::new(10, 9, 0, 8), v6: Some(V6) };
        for (i, s) in segs.iter().enumerate() {
            assert!(valid(s, both), "segment {i}");
            assert_eq!(&s[..4], &[0x60, 0, 0, 0], "its traffic class and flow label as they were");
            assert_eq!((usize::from(u16::from_be_bytes([s[4], s[5]])), s[6], s[7]), (s.len() - 40, 6, 64));
            assert_eq!(u32::from_be_bytes(s[44..48].try_into().unwrap()), 1000 + 1428 * i as u32);
            // ECE on each; CWR on the first only, FIN and PSH on the last only.
            assert_eq!(s[53], [0xd0, 0x50, 0x59][i], "segment {i}'s flags");
            assert_eq!(sum6(s), 0xffff, "segment {i}'s TCP checksum verifies");
            joined.extend_from_slice(&s[60..]);
        }
        assert_eq!(joined, data);
        // ECN: gso_type 0x84 is cut the same.
        let mut ecn = tso((14 + 40, 16));
        ecn[1] = 0x84;
        assert_eq!(cut(&ecn).unwrap(), segs);
        // Held first, in their order, ahead of what was held.
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        let q = Queue { packets: VecDeque::from([b"held".to_vec()]), bytes: 4, ..Queue::default() };
        h.held.lock().unwrap().insert(both.v4, Arc::new(Entry { mig: 1, v6: Some(V6), q: Mutex::new(q) }));
        h.hold_first(both.v4, 1, feed(&[tso((14 + 40, 16))]));
        assert_eq!(h.entry(both.v4).unwrap().q.lock().unwrap().packets, [&segs[..], &[b"held".to_vec()]].concat());
        // Its checksum asked for anywhere but TCP's own field, as for one packet: dropped.
        assert_eq!(cut(&tso((14 + 20, 16))), None, "IPv4's offset");
        assert_eq!(cut(&tso((14 + 40, 6))), None, "UDP's field");
        let mut v4 = tso((14 + 40, 16));
        v4[1] = 1;
        assert_eq!(cut(&v4), None, "TCPv4 GSO of an IPv6 frame");
        let mut hop = tso((14 + 40, 16));
        hop[12 + 14 + 6] = 0;
        assert_eq!(cut(&hop), None, "an extension header");
        let mut tiny = tso((14 + 40, 16));
        tiny[4..6].copy_from_slice(&(MIN_MSS as u16 - 1).to_le_bytes());
        assert_eq!(cut(&tiny), None, "under MIN_MSS");
        assert_eq!(from_tap(&tso((14 + 40, 16)), 1000), Some(Err(3)), "over the room left: counted, not made");
        // A jumbo segment (a payload of 65,500 with a gso_size of 65,535) would be more than a frame.
        let big = vec![7u8; 65500];
        let jumbo = |mss: u16| tso6_frame(&big, mss, (14 + 40, 16));
        assert_eq!(cut(&jumbo(65535)), None, "more than a frame");
        let segs = cut(&jumbo(65535 - 60)).unwrap();
        assert!(segs.len() == 2 && segs[0].len() == MAX_FRAME && segs.iter().all(|s| valid(s, both) && sum6(s) == 0xffff));
    }

    /// An IPv6 straggler to a let-go /128 that moved on is re-sent by `resend6`, to its own
    /// destination, its hop limit down by one; with a hop limit of 1, no IPv6 raw socket, or for
    /// another /128 with the same low 32 bits it is not. IPv4 ones still need `resend`.
    #[test]
    fn ipv6_stragglers_are_re_sent_by_their_own_socket() {
        let (mut h, _w) = paired();
        let ip = Ipv4Addr::new(10, 9, 0, 8);
        h.gone.lock().unwrap().insert(ip, Gone { v6: Some(V6), ..Gone::new(true) });
        let counts = |h: &Holder| h.gone.lock().unwrap().get(&ip).map(|g| (g.resent, g.dropped)).unwrap();
        {
            let _rx = h.rx.lock().unwrap();
            assert!(!h.straggler(ip, &mut udp6_to(V6)), "no IPv6 raw socket");
        }
        assert_eq!(counts(&h), (0, 1));
        h.resend6 = Some(h.tun.try_clone().unwrap());
        let _rx = h.rx.lock().unwrap();
        assert!(!h.straggler(ip, &mut udp_to(ip)), "nor does it re-send IPv4");
        assert_eq!(counts(&h), (0, 2));
        let mut last = udp6_to(V6);
        last[7] = 1;
        assert!(!h.straggler(ip, &mut last), "its hop limit spent");
        assert!(!h.straggler(ip, &mut udp6_to("fd00:8::a09:8".parse().unwrap())), "another's, not counted");
        assert_eq!(counts(&h), (0, 3));
        let mut p = udp6_to(V6);
        assert!(h.straggler(ip, &mut p));
        drop(_rx);
        assert_eq!(p[7], 63);
        let mut sent = Vec::new();
        h.drain_stragglers(|to, p| {
            sent.push((to, p.to_vec()));
            true
        });
        assert_eq!(sent, [(ip, p.clone())]);
        assert_eq!(counts(&h), (1, 3));
        // `resend` sends it to its own destination, not to the IPv4 address.
        let to = sockaddr6(V6);
        assert_eq!((i32::from(to.sin6_family), to.sin6_port, to.sin6_addr.s6_addr, to.sin6_flowinfo, to.sin6_scope_id), (libc::AF_INET6, 0, V6.octets(), 0, 0));
        assert_eq!(dest(&p), Some((ip, Some(V6))));
        assert_eq!(dest(&udp_to(ip)), Some((ip, None)));
        assert_eq!(dest(&p[..39]), None);
    }

    /// A fake handoff target on `l`: confirms each `SYNC`, answers `SWITCH` with `switch_ack`,
    /// and counts the packets it got in its final reply. Returns those packets. Its reads are
    /// bounded: a sender that broke the stream without ending it fails the test, not hangs it
    /// (#1069).
    fn fake_target(l: std::net::TcpListener, switch_ack: u8) -> std::thread::JoinHandle<Vec<Vec<u8>>> {
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            c.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
            let mut got = Vec::new();
            loop {
                let mut head = [0u8; 4];
                c.read_exact(&mut head).unwrap();
                match u32::from_be_bytes(head) {
                    SYNC => c.write_all(b"s").unwrap(),
                    SWITCH => c.write_all(&[switch_ack]).unwrap(),
                    0 => break,
                    len => {
                        let mut p = vec![0u8; len as usize];
                        c.read_exact(&mut p).unwrap();
                        got.push(p);
                    }
                }
            }
            c.write_all(format!("{}\n", json!({"injected": got.len(), "dropped": 0})).as_bytes()).unwrap();
            got
        })
    }

    /// #512: a target that could not take the address over says so (`b'n'`): the handover fails,
    /// but the stream goes on, so nothing held is dropped, and the address is not let go of as
    /// moved (its stragglers would be re-sent into the route that still leads here). It routes
    /// the address itself: no route is owed here (#539). Packets on the device that no reader
    /// took (a busy host's), more than one pass of them, go on the stream too, not dropped (#539).
    #[test]
    fn a_refused_switch_keeps_the_stream() {
        const LATE: usize = PASS + 100;
        for (ack, took) in [(b'w', true), (b'n', false)] {
            let (h, w) = paired();
            let ip = Ipv4Addr::new(10, 9, 0, 8);
            let q = Queue { packets: VecDeque::from(vec![udp_to(ip); 3]), bytes: 3 * 29, ..Queue::default() };
            h.held.lock().unwrap().insert(ip, Arc::new(Entry { mig: 1, v6: None, q: Mutex::new(q) }));
            // More than a pass: refused, the device is read until it is empty, not one pass of it.
            let late = [&vnet_hdr(0, 0, (0, 0))[..], &udp_to(ip)].concat();
            let buf = 4i32 << 20;
            unsafe { libc::setsockopt(w.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF, (&buf as *const i32).cast(), 4) };
            for _ in 0..LATE {
                assert_eq!(unsafe { libc::write(w.as_raw_fd(), late.as_ptr().cast(), late.len()) }, late.len() as isize, "{}", std::io::Error::last_os_error());
            }
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let target = fake_target(l, ack);
            let conn = TcpStream::connect(addr).unwrap();
            let switch = std::cell::Cell::new(false);
            let (stats, switched) = send(&h, ip, 1, &conn, true, || {
                switch.set(true);
                Ok(())
            })
            .unwrap();
            // Ended here, a stream the sender broke off ends the target's read too.
            drop(conn);
            let got = target.join().expect("the target got the whole stream");
            assert!(switched.is_ok() && switch.get() == took, "{}: refused, nothing owed or routed here", ack as char);
            assert_eq!(
                (got.len(), stats.packets, stats.injected, stats.dropped, stats.dropped_target),
                (3 + LATE, 3 + LATE as u64, 3 + LATE as u64, 0, 0),
                "{}",
                ack as char
            );
            assert!(h.entry(ip).is_none(), "{}: no longer held", ack as char);
            let moved = h.gone.lock().unwrap().get(&ip).map(|g| g.moved);
            assert_eq!(moved, Some(took), "{}: stragglers re-sent only once it moved", ack as char);
        }
    }

    /// The reader thread queues packets all through a release: those it queues after the last
    /// hand-over must not be discarded with the queue (#365). Read after `unhold`, they are
    /// stragglers (counted there, with no raw socket to re-send them by).
    #[test]
    fn a_release_discards_nothing_the_reader_queues() {
        let (h, w) = paired();
        let ip = Ipv4Addr::new(10, 9, 0, 8);
        let (p, stop) = ([&vnet_hdr(0, 0, (0, 0))[..], &udp_to(ip)].concat(), AtomicBool::new(false));
        std::thread::scope(|s| {
            s.spawn(|| {
                while !stop.load(Ordering::SeqCst) {
                    unsafe { libc::write(w.as_raw_fd(), p.as_ptr().cast(), p.len()) };
                }
            });
            s.spawn(|| {
                let mut buf = vec![0u8; MAX_FRAME];
                while !stop.load(Ordering::SeqCst) {
                    h.read_one(&mut buf);
                }
            });
            let dropped: Vec<u64> = (0..10)
                .map(|mig| {
                    h.held.lock().unwrap().insert(ip, Arc::new(Entry { mig, v6: None, q: Mutex::default() }));
                    let (stats, switched) = h.release_local(ip, mig, &mut |_| true, || Ok(()), Duration::ZERO).unwrap();
                    switched.unwrap();
                    stats.dropped
                })
                .collect();
            stop.store(true, Ordering::SeqCst);
            assert!(dropped.iter().all(|&d| d == 0), "{dropped:?}");
        });
    }

    #[test]
    fn held_frames_are_a_length_and_the_packet() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut s, _) = l.accept().unwrap();
        let mut out = Out { buf: Vec::new(), broken: false, conn: &c };
        assert!(out.frame(b"one") && out.frame(b"three") && out.flush(Instant::now() + FLUSH_WAIT));
        let mut got = [0u8; 16];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"\0\0\0\x03one\0\0\0\x05three");
    }

    /// Reserve a distinct test address for as long as its UDP port remains bound.
    /// All concurrent root test processes share this port allocator.
    fn root_address() -> (std::net::UdpSocket, std::net::Ipv4Addr) {
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let [hi, lo] = reservation.local_addr().unwrap().port().to_be_bytes();
        (reservation, std::net::Ipv4Addr::new(198, 18, hi, lo))
    }

    /// Needs root: `sudo cargo test -- --ignored`. A TSO frame the kernel's TCP puts on a tap
    /// opened as Firecracker opens one (a 12-byte virtio-net header, checksum and TSO4 offload)
    /// is cut into segments that carry the stream as sent, each valid (#411). The test answers
    /// the host's SYN itself, as a guest would.
    #[test]
    #[ignore]
    fn a_kernel_tso_frame_is_cut_into_valid_segments() {
        let _root = crate::test_util::root_net_lock();
        let tap = format!("tso{:x}t0", std::process::id());
        let (_address, ip) = root_address();
        crate::net::create_tap(&tap, "test").unwrap();
        let raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        assert!(raw >= 0, "open /dev/net/tun: {}", std::io::Error::last_os_error());
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut req = crate::net::ifreq(&tap).unwrap();
        req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short;
        let hdr: libc::c_int = 12;
        let ok = |what: &str, r: libc::c_int| assert_eq!(r, 0, "{what}: {}", std::io::Error::last_os_error());
        unsafe {
            ok("TUNSETIFF", libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &req));
            ok("TUNSETVNETHDRSZ", libc::ioctl(fd.as_raw_fd(), 0x4004_54d8, &hdr));
            ok("TUNSETOFFLOAD", libc::ioctl(fd.as_raw_fd(), 0x4004_54d0, 0x3 as libc::c_ulong /* CSUM, TSO4 */));
        }
        crate::net::set_link_up(&tap, true).unwrap();
        crate::net::attach(ip.into(), &tap).unwrap();
        let mut buf = vec![0u8; 70000];
        let mut next = |what: &dyn Fn(&[u8]) -> bool| loop {
            assert!(crate::util::readable(&fd, Duration::from_secs(5)).unwrap(), "no frame came");
            let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 && what(&buf[..n as usize]) {
                break buf[..n as usize].to_vec();
            }
        };
        let tcp = |f: &[u8]| f.len() > 12 + 14 + 40 && f[12 + 12..12 + 14] == [8, 0] && f[12 + 14 + 9] == 6;
        let data: Vec<u8> = (0..60000u32).map(|i| (i % 251) as u8).collect();
        let sent = data.clone();
        let sender = std::thread::spawn(move || {
            let mut c = TcpStream::connect((ip, 7000)).unwrap();
            c.write_all(&sent).unwrap();
            c
        });
        // Its SYN, answered: a SYN-ACK with an MSS of 1460 and a 64 KiB window.
        let syn = next(&|f| tcp(f) && f[12 + 14 + 33] == 0x02);
        let p = &syn[26..];
        let mut synack = [&p[16..20], &p[12..16]].concat();
        synack.splice(0..0, [0x45, 0, 0, 44, 0, 0, 0x40, 0, 64, 6, 0, 0]);
        let isn = u32::from_be_bytes(p[24..28].try_into().unwrap());
        synack.extend_from_slice(&[0x1b, 0x58]);
        synack.extend_from_slice(&p[20..22]);
        synack.extend_from_slice(&5000u32.to_be_bytes());
        synack.extend_from_slice(&(isn + 1).to_be_bytes());
        synack.extend_from_slice(&[0x60, 0x12, 0xff, 0xff, 0, 0, 0, 0, 2, 4, 0x05, 0xb4]);
        let sum = !sum16(&synack[..20]);
        synack[10..12].copy_from_slice(&sum.to_be_bytes());
        let sum = !sum16(&[&synack[12..20], &[0, 6, 0, 24], &synack[20..]].concat());
        synack[36..38].copy_from_slice(&sum.to_be_bytes());
        let frame = [&[0u8; 12][..], &crate::net::GATEWAY_MAC, &crate::net::GUEST_MAC, &[8, 0], &synack].concat();
        assert_eq!(unsafe { libc::write(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) }, frame.len() as isize);
        let tso = next(&|f| tcp(f) && f[1] & 0x7f == 1);
        let segs = cut(&tso).unwrap();
        let (first, mut joined) = (u32::from_be_bytes(segs[0][24..28].try_into().unwrap()), Vec::new());
        assert!(segs.len() >= 2, "{} segments", segs.len());
        for s in &segs {
            let pseudo = [&s[12..20], &[0, 6], &(s.len() as u16 - 20).to_be_bytes()].concat();
            assert!(ipv4_header_csum_ok(s) && sum16(&[&pseudo[..], &s[20..]].concat()) == 0xffff && s.len() - 40 <= 1460);
            assert_eq!(u32::from_be_bytes(s[24..28].try_into().unwrap()), first + joined.len() as u32, "in sequence");
            joined.extend_from_slice(&s[40..]);
        }
        let at = (first - isn - 1) as usize;
        assert_eq!(joined, data[at..at + joined.len()], "the stream as sent");
        drop(fd);
        crate::net::delete_tap(&tap);
        drop(sender);
    }

    /// A tap opened as Firecracker opens one (without its offloads), deleted when dropped.
    struct TestTap {
        name: String,
        fd: OwnedFd,
    }

    impl Drop for TestTap {
        fn drop(&mut self) {
            crate::net::delete_tap(&self.name);
        }
    }

    fn test_tap(prefix: &str) -> TestTap {
        let name = format!("{prefix}{:x}t0", std::process::id());
        crate::net::create_tap(&name, "test").unwrap();
        let raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        assert!(raw >= 0, "open /dev/net/tun: {}", std::io::Error::last_os_error());
        let t = TestTap { name, fd: unsafe { OwnedFd::from_raw_fd(raw) } };
        let mut req = crate::net::ifreq(&t.name).unwrap();
        req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
        assert_eq!(unsafe { libc::ioctl(t.fd.as_raw_fd(), libc::TUNSETIFF, &req) }, 0, "TUNSETIFF: {}", std::io::Error::last_os_error());
        crate::net::set_link_up(&t.name, true).unwrap();
        t
    }

    /// A frame off a test tap, as its guest would take it.
    fn read(fd: &OwnedFd) -> bool {
        let mut buf = [0u8; 2048];
        unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) > 0 }
    }

    /// Needs root: `sudo cargo test -- --ignored`. #1245: a guest taking a backlog slowly (32
    /// frames every 100 ms: never a stall) has the target wait all of `TAP_BUDGET` for its tap.
    /// A source on the production waits (not stretched, as `SYNC_WAIT` and the rest are in
    /// unit tests) still gets each answer in time: the stream is never broken, its reply in.
    #[test]
    #[ignore]
    fn a_slowly_taken_backlog_stays_within_the_production_waits() {
        let _root = crate::test_util::root_net_lock();
        let t = test_tap("slo");
        let (_address, ip) = root_address();
        let (p, n) = (udp_to(ip), 3 * crate::net::TAP_QUEUE as usize);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (srv, _) = l.accept().unwrap();
        let stop = AtomicBool::new(false);
        // Bounded: a failed assertion here would otherwise leave the scope waiting for its guest.
        let guest_for = Instant::now();
        std::thread::scope(|s| {
            s.spawn(|| {
                while !stop.load(Ordering::SeqCst) && guest_for.elapsed() < Duration::from_secs(30) {
                    std::thread::sleep(Duration::from_millis(100));
                    (0..32).for_each(|_| {
                        read(&t.fd);
                    });
                }
            });
            let target = s.spawn(|| {
                let mut r = BufReader::new(By { s: srv, at: Instant::now() });
                assert!(wait_start(&mut r, Instant::now() + ACCEPT_WAIT));
                receive(&mut r, ip.into(), &t.name, true, &Mutex::new(false), Instant::now() + crate::migrate::HELD_STREAM, &mut || true)
            });
            // As `send` streams, on the production waits.
            let start = Instant::now();
            write_by(&c, &START.to_be_bytes(), start + Duration::from_secs(1)).unwrap();
            let mut ack = [0u8; 1];
            By { s: &c, at: start + Duration::from_secs(1) }.read_exact(&mut ack).unwrap();
            assert_eq!(&ack, b"a");
            let mut frames = Vec::new();
            for _ in 0..n {
                frames.extend_from_slice(&(p.len() as u32).to_be_bytes());
                frames.extend_from_slice(&p);
            }
            for chunk in frames.chunks(48 << 10) {
                write_by(&c, chunk, Instant::now() + FLUSH_WAIT_BASE).expect("each flush within FLUSH_WAIT");
            }
            write_by(&c, &SYNC.to_be_bytes(), Instant::now() + FLUSH_WAIT_BASE).unwrap();
            let synced = Instant::now();
            By { s: &c, at: synced + SYNC_WAIT_BASE }.read_exact(&mut ack).expect("confirmed within SYNC_WAIT");
            assert_eq!(&ack, b"s");
            let synced = synced.elapsed();
            write_by(&c, &0u32.to_be_bytes(), Instant::now() + FLUSH_WAIT_BASE).unwrap();
            let reply = read_reply(&c, Instant::now() + REPLY_WAIT_BASE).expect("the reply within REPLY_WAIT");
            stop.store(true, Ordering::SeqCst);
            let refused = target.join().unwrap();
            let (injected, dropped) = (reply["injected"].as_u64().unwrap(), reply["dropped"].as_u64().unwrap());
            assert_eq!(injected + dropped, n as u64, "{reply}");
            assert!(refused > 0 && injected > crate::net::TAP_QUEUE as u64, "it waited for the tap: {reply}, refused {refused}");
            // Past the 250 ms the stream allowed before (#1245): the target's injection waited.
            assert!(synced > Duration::from_millis(250), "{reply}: confirmed {synced:?} after SYNC");
        });
    }

    /// Needs root: `sudo cargo test -- --ignored`. More frames than a tap queues (#1245): a guest
    /// taking them, late, gets them all; one that takes none costs one `TAP_STALL`, the rest
    /// refused at once, as is any once it stalled; a paused one (not waited for) costs nothing;
    /// a slow one at most `TAP_BUDGET`. Either way the tap's count of what it refused is not
    /// reported as dropped too (the caller counts the sends that failed). A stream that breaks
    /// off still accounts for its refusals.
    #[test]
    #[ignore]
    fn injecting_past_a_full_tap_waits_for_its_guest() {
        let _root = crate::test_util::root_net_lock();
        let t = test_tap("inj");
        let (tap, fd) = (t.name.as_str(), &t.fd);
        let (_address, ip) = root_address();
        let n = 3 * crate::net::TAP_QUEUE as usize;
        let p = udp_to(ip);
        let drain = |fd: &OwnedFd| while read(fd) {};
        // A guest that starts taking frames only once the tap is full.
        let inj = Injector::new(tap, true).unwrap();
        let (stop, got) = (AtomicBool::new(false), AtomicUsize::new(0));
        // Bounded: a failed assertion here would otherwise leave the scope waiting for its guest.
        let guest_for = Instant::now();
        let sent = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                while !stop.load(Ordering::SeqCst) && guest_for.elapsed() < Duration::from_secs(30) {
                    if read(fd) {
                        got.fetch_add(1, Ordering::SeqCst);
                    } else {
                        std::thread::sleep(Duration::from_micros(50));
                    }
                }
            });
            let sent = (0..n).filter(|_| inj.send(&p)).count();
            crate::test_util::wait_until("the guest to take them", || got.load(Ordering::SeqCst) >= sent);
            stop.store(true, Ordering::SeqCst);
            sent
        });
        assert_eq!((sent, got.load(Ordering::SeqCst), inj.dropped()), (n, n, 0), "refused {}", inj.refused());
        assert!(inj.refused() > 0, "the tap filled");
        // A guest that takes none: one wait, then the rest refused at once, even after it takes one.
        let inj = Injector::new(tap, true).unwrap();
        let start = Instant::now();
        let sent = (0..n).filter(|_| inj.send(&p)).count();
        assert_eq!(sent, crate::net::TAP_QUEUE as usize, "as many as the tap queues");
        assert!(start.elapsed() < TAP_STALL * 5, "{:?}", start.elapsed());
        assert!(inj.refused() >= (n - sent) as u64, "{}", inj.refused());
        assert_eq!(inj.dropped(), 0, "not counted twice");
        // Its ring frees slots a batch at a time.
        assert!((0..64).all(|_| read(fd)) && inj.send(&p), "room for one");
        let start = Instant::now();
        let more = (0..200).filter(|_| inj.send(&p)).count();
        assert!(more < 200 && start.elapsed() < TAP_STALL / 2, "no wait once stalled: {more}, {:?}", start.elapsed());
        drain(fd);
        // A paused guest: never waited for.
        let inj = Injector::new(tap, false).unwrap();
        let start = Instant::now();
        let sent = (0..n).filter(|_| inj.send(&p)).count();
        assert_eq!(sent, crate::net::TAP_QUEUE as usize);
        assert!(start.elapsed() < TAP_STALL / 2, "{:?}", start.elapsed());
        assert_eq!((inj.refused(), inj.dropped()), ((n - sent) as u64, 0));
        drain(fd);
        // A guest taking 32 frames every 100 ms (its ring frees slots a batch at a time): waited
        // for within the budget, then not.
        let inj = Injector::new(tap, true).unwrap();
        let stop = AtomicBool::new(false);
        // Bounded: a failed assertion here would otherwise leave the scope waiting for its guest.
        let guest_for = Instant::now();
        let (sent, took) = std::thread::scope(|s| {
            s.spawn(|| {
                while !stop.load(Ordering::SeqCst) && guest_for.elapsed() < Duration::from_secs(30) {
                    std::thread::sleep(Duration::from_millis(100));
                    (0..32).for_each(|_| {
                        read(fd);
                    });
                }
            });
            let start = Instant::now();
            let sent = (0..n).filter(|_| inj.send(&p)).count();
            stop.store(true, Ordering::SeqCst);
            (sent, start.elapsed())
        });
        assert!(sent > crate::net::TAP_QUEUE as usize && sent < n, "{sent}");
        assert!(took < TAP_BUDGET + TAP_STALL * 3, "{took:?}");
        assert_eq!(inj.dropped(), 0);
        drain(fd);
        // A stream broken off (no end, no reply): its refusals are still accounted for.
        let before = tap_tx_dropped(tap).unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (srv, _) = l.accept().unwrap();
        let frames = 2 * crate::net::TAP_QUEUE as usize;
        let mut stream = START.to_be_bytes().to_vec();
        for _ in 0..frames {
            stream.extend_from_slice(&(p.len() as u32).to_be_bytes());
            stream.extend_from_slice(&p);
        }
        let sender = std::thread::spawn(move || {
            c.write_all(&stream).unwrap();
            let mut ack = [0u8; 1];
            c.read_exact(&mut ack).unwrap();
            // Broken off: no end.
            drop(c);
        });
        let mut r = BufReader::new(By { s: srv, at: Instant::now() + Duration::from_secs(10) });
        assert!(wait_start(&mut r, Instant::now() + Duration::from_secs(10)));
        let accounted = receive(&mut r, ip.into(), tap, true, &Mutex::new(false), Instant::now() + Duration::from_secs(10), &mut || true);
        sender.join().unwrap();
        let counted = tap_tx_dropped(tap).unwrap() - before;
        assert!(counted > 0 && accounted == counted, "accounted {accounted} of the tap's {counted}");
        drain(fd);
    }

    /// Needs root: `sudo cargo test -- --ignored`. A sender that looked the route up before a
    /// release hands its packet to the device after it (#254), here by binding to the device:
    /// it is re-sent to where the address went, never lost uncounted.
    #[test]
    #[ignore]
    fn stragglers_follow_the_address() {
        let _root = crate::test_util::root_net_lock();
        let (a, b) =
            (Holder::new(&format!("tsa{:x}h", std::process::id())).unwrap().unwrap(), Holder::new(&format!("tsb{:x}h", std::process::id())).unwrap().unwrap());
        let (_address, ip) = root_address();
        a.hold(ip.into(), 1).unwrap();
        let mut none = |_: &[u8]| true;
        let (_, switched) = a.release_local(ip, 1, &mut none, || b.hold(ip.into(), 2), Duration::ZERO).unwrap();
        switched.unwrap();
        let s = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let dev = a.dev.as_bytes();
        assert_eq!(unsafe { libc::setsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_BINDTODEVICE, dev.as_ptr().cast(), dev.len() as u32) }, 0);
        s.send_to(b"late", (ip, 9)).unwrap();
        let mut got = Vec::new();
        let mut sink = |p: &[u8]| {
            got.push(p.to_vec());
            true
        };
        // a re-sends the straggler to b's device; wait until b has queued it.
        crate::test_util::wait_until("b to queue the straggler", || !b.entry(ip).unwrap().q.lock().unwrap().packets.is_empty());
        let (stats, _) = b.release_local(ip, 2, &mut sink, || Ok(()), Duration::ZERO).unwrap();
        b.forget(ip, 2);
        let _ = crate::net::route_dev(false, ip.into(), b.ifindex);
        assert_eq!((stats.packets, stats.dropped), (1, 0));
        assert!(got[0].ends_with(b"late") && got[0][8] == 63, "{got:?}");
        // A fragment with IP ID 0 would get a new ID if re-sent (no longer reassembling with its
        // siblings): counted as dropped instead. One with an ID is re-sent.
        let counts = |a: &Holder| a.gone.lock().unwrap().get(&ip).map(|g| (g.resent, g.dropped)).unwrap();
        let mut frag = [0x45u8, 0, 0, 28, 0, 0, 0x20, 0, 64, 17, 0, 0, 10, 100, 254, 1, 10, 100, 254, 9, 0, 1, 0, 9, 0, 8, 0, 0];
        frag[16..20].copy_from_slice(&ip.octets());
        let before = counts(&a);
        if a.straggler(ip, &mut frag) {
            a.drain_stragglers(|ip, p| a.resend(ip, p));
        }
        assert_eq!(counts(&a), (before.0, before.1 + 1));
        frag[4..6].copy_from_slice(&[0x12, 0x34]);
        if a.straggler(ip, &mut frag) {
            a.drain_stragglers(|ip, p| a.resend(ip, p));
        }
        assert_eq!(counts(&a), (before.0 + 1, before.1 + 1));
    }

    /// Needs root: `sudo cargo test -- --ignored`. `stragglers_follow_the_address` for an IPv6
    /// address (`vm_ipv6_prefix`): held with its /32, its /128 goes to the hold device, and a
    /// straggler for it is re-sent by the IPv6 raw socket to where it went, which holds it.
    #[test]
    #[ignore]
    fn ipv6_stragglers_follow_the_address() {
        let _root = crate::test_util::root_net_lock();
        let (a, b) =
            (Holder::new(&format!("t6a{:x}h", std::process::id())).unwrap().unwrap(), Holder::new(&format!("t6b{:x}h", std::process::id())).unwrap().unwrap());
        let (_address, ip) = root_address();
        let v6 = Ipv6Addr::from((0xfd00_0e2e_u128 << 96) | u128::from(u32::from(ip)));
        let addr = crate::net::VmAddr { v4: ip, v6: Some(v6) };
        a.hold(addr, 1).unwrap();
        assert_eq!(a.entry(ip).unwrap().v6, Some(v6), "IPv6 on on the hold device: {}", a.dev);
        let mut none = |_: &[u8]| true;
        let (_, switched) = a.release_local(ip, 1, &mut none, || b.hold(addr, 2), Duration::ZERO).unwrap();
        switched.unwrap();
        assert!(a.resend6.is_some());
        // As the reader takes one off the device after the switch.
        let mut p = [&udp6_to(v6)[..], b"late"].concat();
        p[5] += 4;
        {
            let _rx = a.rx.lock().unwrap();
            assert!(a.straggler(ip, &mut p));
        }
        a.drain_stragglers(|ip, p| a.resend(ip, p));
        crate::test_util::wait_until("b to queue the straggler", || !b.entry(ip).unwrap().q.lock().unwrap().packets.is_empty());
        let mut got = Vec::new();
        let mut sink = |p: &[u8]| {
            got.push(p.to_vec());
            true
        };
        let (stats, _) = b.release_local(ip, 2, &mut sink, || Ok(()), Duration::ZERO).unwrap();
        b.forget(ip, 2);
        let _ = crate::net::route_dev(false, addr, b.ifindex);
        assert_eq!((stats.packets, stats.dropped), (1, 0));
        assert_eq!(got, [p.clone()]);
        assert!(got[0].ends_with(b"late") && got[0][7] == 63, "{got:?}");
    }
}
