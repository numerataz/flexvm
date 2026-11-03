//! Host networking: every VM gets a /32 routed to its own tap, and with `vm_ipv6_prefix` a
//! /128 beside it (`VmAddr`).
//!
//! All taps share one MAC, as do all guests, so moving a VM between hosts is just moving
//! its route (plus, with `announce_dev`, a gratuitous ARP for proxy-ARP LAN peers).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{
    c_int, IFA_ADDRESS, IFA_LOCAL, IFLA_ADDRESS, IFLA_IFALIAS, NDA_DST, NDA_LLADDR, NLMSG_ERROR, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST,
    NUD_PERMANENT, RTA_DST, RTA_GATEWAY, RTA_OIF, RTM_DELLINK, RTM_DELROUTE, RTM_NEWADDR, RTM_NEWNEIGH, RTM_NEWROUTE, RTM_SETLINK, RTN_UNICAST, RTPROT_STATIC,
    RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN,
};

use crate::bail;
use crate::util::Result;

pub const GATEWAY_MAC: [u8; 6] = [0x06, 0x00, 0xa9, 0xfe, 0x01, 0x01];
pub const GUEST_MAC: [u8; 6] = [0x06, 0x00, 0xac, 0x10, 0x00, 0x02];

/// `aa:bb:...`, as Firecracker takes it.
pub fn mac_string(mac: &[u8; 6]) -> String {
    mac.map(|b| format!("{b:02x}")).join(":")
}

fn socket(domain: c_int, kind: c_int, protocol: c_int, what: &str) -> Result<OwnedFd> {
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    crate::syscall_check!(fd < 0, "{what}");
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn send_to<A>(fd: &OwnedFd, buf: &[u8], addr: &A) -> isize {
    let len = std::mem::size_of::<A>() as libc::socklen_t;
    unsafe { libc::sendto(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0, (addr as *const A).cast(), len) }
}

/// Down, a tap takes no packets, so Firecracker writes none into guest memory.
pub fn set_link_up(name: &str, up: bool) -> Result<()> {
    let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0, "socket")?;
    let mut req = ifreq(name)?;
    let done = unsafe {
        libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req) >= 0 && {
            let flags = &mut req.ifr_ifru.ifru_flags;
            *flags = if up { *flags | libc::IFF_UP as libc::c_short } else { *flags & !(libc::IFF_UP as libc::c_short) };
            libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS, &req) >= 0
        }
    };
    crate::syscall_check!(!done, "set {name} {}", if up { "up" } else { "down" });
    Ok(())
}

/// Whether frames wait on a tap for its guest, through a copy of Firecracker's descriptor of
/// it (`tap_fd_of`): tun's ring is not empty. Paused vCPUs post no rx buffers, so a VM paused
/// with frames there loses them when the tap goes (a migration, `checkpoint --stop`, a
/// suspend), and no counter shows it: a guest slow to refill under load leaves hundreds (#136).
pub fn tap_queued(fd: &OwnedFd) -> Result<bool> {
    let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let n = crate::util::eintr(|| unsafe { libc::poll(&mut pfd, 1, 0) }).map_err(|e| format!("poll: {e}"))?;
    Ok(n > 0 && pfd.revents & libc::POLLIN != 0)
}

/// Reads off the frames queued on a tap (`tap_fd_of`, non-blocking as Firecracker opened it),
/// each with its virtio-net header, handing each to `each` as it is read: for a VM leaving
/// them, so they are passed on or counted. Returns how many.
pub fn read_tap_queue(fd: &OwnedFd, each: &mut dyn FnMut(&[u8])) -> u64 {
    // A frame with its virtio-net header, up to the 64 KiB a GSO frame can be.
    let mut buf = vec![0u8; 65562 + 64];
    let mut n = 0;
    // Do not change shared descriptor flags; keep polling per frame if it is blocking after all.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    let nonblocking = flags >= 0 && flags & libc::O_NONBLOCK != 0;
    if !tap_queued(fd).unwrap_or(false) {
        return 0;
    }
    // Bounded by the ring (TAP_QUEUE), even if more traffic arrives meanwhile.
    while n < u64::from(TAP_QUEUE) {
        let Ok(len) = crate::util::eintr(|| unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) }) else { break };
        if len == 0 {
            break;
        }
        let len = len as usize;
        each(&buf[..len]);
        n += 1;
        if !nonblocking && !tap_queued(fd).unwrap_or(false) {
            break;
        }
    }
    n
}

/// Process `pid`'s descriptor attached to `tap` (its fdinfo says `iff: TAP`), duplicated here
/// (`pidfd_getfd`), to watch its queue. Reading a tun fdinfo takes RTNL, so this can wait on
/// other network changes: done before the VM's address is held.
pub fn tap_fd_of(pid: u32, tap: &str) -> Result<OwnedFd> {
    let pidfd = crate::util::pidfd_open(pid).map_err(|e| format!("pidfd_open {pid}: {e}"))?;
    let want = format!("iff:\t{tap}\n");
    for entry in std::fs::read_dir(format!("/proc/{pid}/fdinfo"))? {
        let entry = entry?;
        let Some(target) = entry.file_name().to_str().and_then(|s| s.parse::<c_int>().ok()) else { continue };
        if !std::fs::read_to_string(entry.path()).is_ok_and(|s| s.contains(&want)) {
            continue;
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), target, 0) };
        crate::syscall_check!(fd < 0, "pidfd_getfd {pid} {target}");
        return Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) });
    }
    bail!("process {pid} has no descriptor attached to {tap}")
}

/// Without an address on the tap, rp_filter (even loose) drops what the guest sends while
/// its address is routed elsewhere (`hold`); a per-tap `rp_filter=0` loses to `all`=2.
pub const TAP_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 2);

/// Room for the packets a migration held, injected all at once (default 1000).
pub const TAP_QUEUE: u32 = 4096;

/// The guests' IPv6 gateway on every tap (`tap_ipv6`), link-local as a router's is; a guest's
/// neighbour entry for it is pinned to `GATEWAY_MAC`, as its IPv4 gateway's is.
pub const TAP_ADDR6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

/// A VM's addresses as its host routes them: its IPv4 address, and with `vm_ipv6_prefix` its IPv6
/// one (`Config::vm_addr`), which goes wherever the IPv4 one does (the tap's guard, neighbour
/// entry and route). Without an IPv6 address every helper does just what it does for the IPv4 one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmAddr {
    pub v4: Ipv4Addr,
    pub v6: Option<Ipv6Addr>,
}

impl From<Ipv4Addr> for VmAddr {
    fn from(v4: Ipv4Addr) -> VmAddr {
        VmAddr { v4, v6: None }
    }
}

impl VmAddr {
    /// Its IPv4 address, then its IPv6 one if it has one.
    pub fn each(self) -> impl Iterator<Item = IpAddr> {
        std::iter::once(IpAddr::V4(self.v4)).chain(self.v6.map(IpAddr::V6))
    }
}

/// A tap of exactly `name` (`create_tap_with`).
#[cfg(test)]
pub fn create_tap(name: &str, owner: &str) -> Result<()> {
    ifreq(name)?;
    create_tap_with(owner, |fd| claim_tap(fd, name).map(|()| name.to_string()).map_err(|e| format!("create tap {name}: {e}").into())).map(|_| ())
}

/// A template tap, trying a free suffix if another PID namespace has the same name.
pub fn create_free_tap(name: &str, owner: &str) -> Result<String> {
    ifreq(name)?;
    create_tap_with(owner, |fd| free_tun(fd, name, TAP_FLAGS).map_err(|e| format!("create tap {name}: {e}").into()))
}

/// Ioctls and rtnetlink, as spawning `ip` costs tens of milliseconds. `owner` becomes the
/// tap's alias (`host::tap_alias`), set before the tap is made persistent: a tap left
/// behind always names its owner, and garbage collection goes by that, never by the name.
/// `claim` attaches the descriptor it is given to a new tap (`claim_tap`) and names it.
pub fn create_tap_with(owner: &str, claim: impl FnOnce(&OwnedFd) -> Result<String>) -> Result<String> {
    // Subscribed before the tap exists: udev's event for it cannot come before.
    create_indexed_tap(owner, claim).map(|(name, _)| name)
}

pub fn create_indexed_tap(owner: &str, claim: impl FnOnce(&OwnedFd) -> Result<String>) -> Result<(String, u32)> {
    make_tap(owner, udev_monitor(), claim)
}

/// Never a leaked tap of a dead process with this name, nor its routes.
const TAP_FLAGS: libc::c_short = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;

/// Attaches `fd` to a new tap `name`. EBUSY: a device has the name (another process's).
pub fn claim_tap(fd: &OwnedFd, name: &str) -> std::io::Result<()> {
    claim_tun(fd, name, TAP_FLAGS)
}

/// Whether a claim failed only because the name is taken.
pub fn name_taken(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EBUSY | libc::EEXIST))
}

fn claim_tun(fd: &OwnedFd, dev: &str, flags: libc::c_short) -> std::io::Result<()> {
    let mut req = ifreq(dev).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    req.ifr_ifru.ifru_flags = flags | libc::IFF_TUN_EXCL as libc::c_short;
    crate::util::eintr(|| unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &req) }).map(|_| ())
}

/// Claim a new device, never attaching to an existing one, even a persistent TUN.
pub(crate) fn free_tun(fd: &OwnedFd, name: &str, flags: libc::c_short) -> std::io::Result<String> {
    free_name(name, |dev| claim_tun(fd, dev, flags))
}

/// How many hex suffixes a device name tries after its own: a short pid leaves room for more,
/// but past this many taken names something other than a namesake is refusing them.
const NAME_SUFFIXES: u64 = 256;

/// The old name first, then hex suffixes. Only a failed claim retries: no sysfs race,
/// and no retry after a later setup failure might have left a persistent device.
fn free_name(name: &str, mut claim: impl FnMut(&str) -> std::io::Result<()>) -> std::io::Result<String> {
    let too_long = |dev: &str| dev.len() >= libc::IFNAMSIZ;
    if too_long(name) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("interface name {name:?} is over {} bytes", libc::IFNAMSIZ - 1)));
    }
    let mut dev = name.to_string();
    let mut n = 0u64;
    loop {
        match claim(&dev) {
            Ok(()) => return Ok(dev),
            Err(e) if name_taken(&e) => {}
            Err(e) => return Err(e),
        }
        dev = format!("{name}{n:x}");
        n += 1;
        if n > NAME_SUFFIXES || too_long(&dev) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{name} and its {} suffixes are taken (no free device names within {} bytes)", n - 1, libc::IFNAMSIZ - 1),
            ));
        }
    }
}

/// `create_tap_with`, with `udev` (if any) handed to the tap's watcher (`keep_mac_from_udev`).
fn make_tap(owner: &str, udev: Option<OwnedFd>, claim: impl FnOnce(&OwnedFd) -> Result<String>) -> Result<(String, u32)> {
    if owner.len() >= 256 {
        bail!("tap: owner {owner:?} is over 255 bytes (a shorter run directory)");
    }
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    crate::syscall_check!(fd < 0, "/dev/net/tun");
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let name = claim(&fd)?;
    let name = name.as_str();
    // Until TUNSETPERSIST the tap goes with `fd`, so with this process.
    let index = ifindex(name)?;
    let mut alias = ifinfomsg(index);
    attr(&mut alias, IFLA_IFALIAS, owner.as_bytes());
    netlink(RTM_SETLINK, 0, &alias).map_err(|e| format!("tap {name}: its owner: {e}"))?;
    crate::syscall_check!(unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETPERSIST, 1) } < 0, "create tap {name}");
    drop(fd);
    let made = (|| -> Result<()> {
        let mut addr = [&[libc::AF_INET as u8, 32, 0, RT_SCOPE_HOST][..], &index.to_ne_bytes()].concat();
        attr(&mut addr, IFA_LOCAL, &TAP_ADDR.octets());
        attr(&mut addr, IFA_ADDRESS, &TAP_ADDR.octets());
        netlink(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &addr)?;
        set_mac(index, &GATEWAY_MAC)?;
        let mut q = ifreq(name)?;
        q.ifr_ifru.ifru_metric = TAP_QUEUE as i32;
        let sock = socket(libc::AF_INET, libc::SOCK_DGRAM, 0, "socket")?;
        crate::syscall_check!(unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFTXQLEN as _, &q) } < 0, "txqueuelen of {name}");
        conf("ipv4", name, "arp_ignore", "3")?;
        // The guest is IPv4 only. With IPv6, the host sends an MLD report out of the tap as
        // it comes up: dropped (tx_dropped) when no Firecracker reads it yet (an arrival's),
        // which reads as a frame lost on its way to the guest. As for the hold device.
        let _ = conf("ipv6", name, "disable_ipv6", "1");
        // Shut until `neighbour` names the VM's address: nothing the guest sends gets out.
        guard(index, None).map_err(|e| format!("tap {name}: {e}"))?;
        set_link_up(name, true)
    })();
    match (&made, udev) {
        (Err(_), _) => delete_link(index, name),
        (Ok(()), Some(udev)) => {
            let tap = name.to_string();
            // Not fatal: neighbour still checks the MAC when the tap is handed to a VM.
            if let Err(e) = std::thread::Builder::new().name("udev-mac".into()).spawn(move || keep_mac_from_udev(&udev, index, &tap, UDEV_RECHECK)) {
                crate::log!("tap {name}: not watching for udev replacing its MAC: {e}");
            }
        }
        (Ok(()), None) => {}
    }
    made.map(|()| (name.to_string(), index))
}

/// How often a tap's watcher checks its MAC, and that it is still there, between udev's events.
const UDEV_RECHECK: std::time::Duration = std::time::Duration::from_secs(5);
const NETLINK_KOBJECT_UEVENT: c_int = 15;
/// The uevent socket's group udev (re)broadcasts each event on once it has handled it (1 is the kernel's).
const UDEV_GROUP: u32 = 2;

/// A socket on udev's monitor group, when udevd runs and sees this network namespace's devices:
/// none without it (nothing to wait for), nor in another namespace than init's (`ip netns exec`
/// keeps /run/udev, but uevents of its devices never reach udev), whose taps udev never touches.
fn udev_monitor() -> Option<OwnedFd> {
    use std::os::unix::fs::MetadataExt;
    let ns = |pid: &str| std::fs::metadata(format!("/proc/{pid}/ns/net")).map(|m| (m.dev(), m.ino())).ok();
    let watched = std::path::Path::new("/run/udev/control").exists() && ns("self").is_some_and(|me| ns("1") == Some(me));
    watched.then(|| uevent_socket(UDEV_GROUP)).flatten()
}

fn uevent_socket(groups: u32) -> Option<OwnedFd> {
    let fd = socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT, "uevent socket").ok()?;
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    (addr.nl_family, addr.nl_groups) = (libc::AF_NETLINK as u16, groups);
    let bound = unsafe { libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_nl).cast(), std::mem::size_of_val(&addr) as libc::socklen_t) };
    (bound == 0).then_some(fd)
}

/// udev's `ACTION` and `IFINDEX` of a message on its monitor group: a `struct monitor_netlink_header`
/// ("libudev", magic 0xfeedcafe big-endian, then native header size, properties offset and length)
/// and `KEY=value` properties, each NUL-terminated. None for anything else.
fn udev_event(msg: &[u8]) -> Option<(&[u8], u32)> {
    let word = |at: usize| Some(u32::from_ne_bytes(msg.get(at..at + 4)?.try_into().ok()?) as usize);
    if msg.get(..8)? != b"libudev\0" || msg.get(8..12)? != 0xfeedcafe_u32.to_be_bytes() {
        return None;
    }
    let (off, len) = (word(16)?, word(20)?);
    let props = msg.get(off..off.checked_add(len)?)?;
    let (mut action, mut index) = (None, None);
    for p in props.split(|&b| b == 0) {
        if let Some(a) = p.strip_prefix(b"ACTION=") {
            action = Some(a);
        } else if let Some(i) = p.strip_prefix(b"IFINDEX=") {
            index = std::str::from_utf8(i).ok()?.parse().ok();
        }
    }
    Some((action?, index?))
}

/// udev (systemd's default `MACAddressPolicy=persistent`) gives a new tap a MAC of its own if it
/// reads the tap's address as the kernel's random one, which it can in the millisecond or so
/// before `create_tap` sets the gateway's; its write then lands whenever its worker gets to it,
/// on a loaded host after `neighbour` checked the MAC and the VM runs: the host drops all the
/// guest sends (to the gateway MAC), so no SYN it is sent is answered (#841). udev broadcasts its
/// event for the tap only once it applied its link settings, so the gateway MAC goes back then.
/// udev may take minutes (its event timeout is 3, and events queue before), or the event may be
/// lost to an overrun: until it comes the MAC is checked every `recheck`, as long as the tap is
/// there (a watcher lives no longer than its tap).
fn keep_mac_from_udev(udev: &OwnedFd, index: u32, name: &str, recheck: std::time::Duration) {
    // A network device's event is a few hundred bytes; a longer one, truncated, is another's.
    let mut buf = [0u8; 8192];
    // By the clock, not each poll's timeout: other devices' events, however many, hold no recheck up.
    let mut next = std::time::Instant::now() + recheck;
    loop {
        let now = std::time::Instant::now();
        if now >= next {
            if !restore_mac(index, name) {
                return;
            }
            next = now + recheck;
        }
        let mut pfd = libc::pollfd { fd: udev.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ms = next.saturating_duration_since(now).as_millis().clamp(1, i32::MAX as u128) as c_int;
        match crate::util::eintr(|| unsafe { libc::poll(&mut pfd, 1, ms) }) {
            Err(_) => {
                restore_mac(index, name);
                return;
            }
            Ok(0) => continue,
            Ok(_) => {}
        }
        let n = unsafe { libc::recv(udev.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        match (n > 0).then(|| udev_event(&buf[..n as usize])).flatten() {
            Some((b"add", i)) if i == index => {
                restore_mac(index, name);
                return;
            }
            Some((b"remove", i)) if i == index => return,
            _ => {}
        }
    }
}

/// Puts the gateway MAC back on tap `name` at `index` if something replaced it, while the
/// index still has that name (as `delete_link`): never another device's. Whether it still has.
fn restore_mac(index: u32, name: &str) -> bool {
    if !has_name(index, name) {
        return false;
    }
    let mac = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok().and_then(|s| parse_mac(&s).ok());
    if mac.is_some_and(|m| m != GATEWAY_MAC) {
        if let Err(e) = set_mac(index, &GATEWAY_MAC) {
            crate::log!("tap {name}: udev replaced its MAC, and putting the gateway's back failed: {e}");
        }
    }
    true
}

pub fn delete_tap(name: &str) {
    if let Ok(index) = ifindex(name) {
        delete_link(index, name);
    }
}

/// By index, while it still has `name`: a tap made since under the name has another
/// index, and one renamed or moved away (its index reused) another name. A rename in
/// between the check and the delete is not caught.
pub fn delete_link(ifindex: u32, name: &str) {
    if has_name(ifindex, name) {
        let _ = netlink(RTM_DELLINK, 0, &ifinfomsg(ifindex));
    }
}

fn has_name(index: u32, name: &str) -> bool {
    let mut now = [0 as libc::c_char; libc::IFNAMSIZ];
    let named = unsafe { libc::if_indextoname(index, now.as_mut_ptr()) };
    !named.is_null() && unsafe { std::ffi::CStr::from_ptr(named) }.to_bytes() == name.as_bytes()
}

/// A longer name is refused: the kernel would take it truncated.
pub fn ifreq(name: &str) -> Result<libc::ifreq> {
    if name.len() >= libc::IFNAMSIZ {
        bail!("interface name {name:?} is over {} bytes", libc::IFNAMSIZ - 1);
    }
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, s) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *d = s as libc::c_char;
    }
    Ok(req)
}

/// Puts the gateway MAC back first: udev (`MACAddressPolicy=persistent`) may have replaced
/// it, leaving the guest's pinned gateway ARP entry pointing nowhere.
pub fn attach(ip: VmAddr, tap: &str) -> Result<()> {
    route(ip, neighbour(ip, tap)?)
}

/// Installs the route using the index retained when the caller readied the tap.
pub fn route(ip: VmAddr, index: u32) -> Result<()> {
    route_dev(true, ip, index)
}

/// `attach` but the route, which a migration target installs at its commit; returns the
/// tap's index.
pub fn neighbour(ip: VmAddr, tap: &str) -> Result<u32> {
    let ifindex = ifindex(tap)?;
    if std::fs::read_to_string(format!("/sys/class/net/{tap}/address")).ok().and_then(|s| parse_mac(&s).ok()) != Some(GATEWAY_MAC) {
        set_mac(ifindex, &GATEWAY_MAC)?;
    }
    // Before the neighbour entry and the route: the tap passes only `ip`'s packets once it is `ip`'s.
    guard(ifindex, Some(ip)).map_err(|e| format!("tap {tap}: {e}"))?;
    if ip.v6.is_some() {
        tap_ipv6(ifindex, tap).map_err(|e| format!("tap {tap}: IPv6 (vm_ipv6_prefix): {e}"))?;
    }
    for dst in ip.each() {
        netlink(RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE, &neigh_msg(ifindex, dst))?;
    }
    Ok(ifindex)
}

/// A permanent neighbour entry for the guest's address `dst` on the tap at `ifindex`: struct ndmsg
/// (family, pad, index, state, flags, type), the address and `GUEST_MAC`.
fn neigh_msg(ifindex: u32, dst: IpAddr) -> Vec<u8> {
    let (family, dst) = match dst {
        IpAddr::V4(v4) => (libc::AF_INET, v4.octets().to_vec()),
        IpAddr::V6(v6) => (libc::AF_INET6, v6.octets().to_vec()),
    };
    let mut neigh = [&[family as u8, 0, 0, 0][..], &ifindex.to_ne_bytes(), &NUD_PERMANENT.to_ne_bytes(), &[0, 0]].concat();
    attr(&mut neigh, NDA_DST, &dst);
    attr(&mut neigh, NDA_LLADDR, &GUEST_MAC);
    neigh
}

/// struct ifaddrmsg's flag for an address with no duplicate address detection (if_addr.h).
const IFA_F_NODAD: u8 = 0x02;

/// IPv6 on tap `name` (at `ifindex`) once a VM with an IPv6 address has it, before its neighbour
/// entry and route: off until then (`make_tap`), so off on every tap without `vm_ipv6_prefix`. No
/// address of the kernel's own (addr_gen_mode 1: no EUI-64 link-local, nor its duplicate address
/// detection), no router advertisements taken (`guard` drops a guest's anyway), and `TAP_ADDR6`
/// without duplicate address detection. What kept IPv6 off on taps, the host's MLD reports as it
/// comes up (and each time the tap does), is dropped on the way out (`multicast_filter`): sent to
/// a tap no Firecracker reads yet (an arrival's), it would count as a frame lost on its way to the
/// guest (tx_dropped). Done again on each `neighbour`: the address goes each time the tap goes down.
fn tap_ipv6(ifindex: u32, name: &str) -> Result<()> {
    let filter = filter_msg(ifindex, CLSACT_EGRESS, &multicast_filter());
    netlink(libc::RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE, &filter).map_err(|e| format!("its multicast filter (cls_bpf): {e}"))?;
    for (key, value) in [("addr_gen_mode", "1"), ("accept_ra", "0"), ("autoconf", "0"), ("disable_ipv6", "0")] {
        conf("ipv6", name, key, value)?;
    }
    netlink(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &tap_addr6_msg(ifindex))?;
    // On already, normally (`flexvm listen`, boot recovery); a VM process finds it off if the
    // prefix was set since. Without it the guest's IPv6 reaches this host only.
    if let Err(e) = ipv6_forward() {
        static LOGGED: std::sync::Once = std::sync::Once::new();
        LOGGED.call_once(|| crate::log!("WARNING: {e}: VMs' IPv6 addresses reach this host only; this is logged once"));
    }
    Ok(())
}

/// `TAP_ADDR6` on the tap at `ifindex`: struct ifaddrmsg (family, prefix length, flags, scope, index).
fn tap_addr6_msg(ifindex: u32) -> Vec<u8> {
    let mut addr = [&[libc::AF_INET6 as u8, 64, IFA_F_NODAD, RT_SCOPE_LINK][..], &ifindex.to_ne_bytes()].concat();
    attr(&mut addr, IFA_ADDRESS, &TAP_ADDR6.octets());
    addr
}

const TC_H_ROOT: u32 = 0xffff_ffff;
const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCQ_PLUG_BUFFER: i32 = 0;
const TCQ_PLUG_RELEASE_INDEFINITE: i32 = 2;
/// Bytes a plugged tap buffers: `sch_plug` drops beyond (counted by `unplug_tap`).
const PLUG_LIMIT: u32 = 16 << 20;
const TCA_STATS: u16 = 3;

/// struct tcmsg (family, pads, ifindex, handle, parent, info) at `ifindex`.
fn tcmsg(ifindex: u32, handle: u32, parent: u32, info: u32) -> Vec<u8> {
    [&[libc::AF_UNSPEC as u8, 0, 0, 0][..], &ifindex.to_ne_bytes(), &handle.to_ne_bytes(), &parent.to_ne_bytes(), &info.to_ne_bytes()].concat()
}

/// The root plug qdisc, with TCA_KIND "plug" and its struct tc_plug_qopt (action, limit).
fn plug_msg(ifindex: u32, action: i32) -> Vec<u8> {
    let mut m = tcmsg(ifindex, 0x1_0000, TC_H_ROOT, 0);
    attr(&mut m, TCA_KIND, b"plug\0");
    attr(&mut m, TCA_OPTIONS, &[&action.to_ne_bytes()[..], &PLUG_LIMIT.to_ne_bytes()].concat());
    m
}

/// clsact's handle and parent, and its ingress hook's (`TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)`).
const CLSACT_HANDLE: u32 = 0xffff_0000;
const TC_H_CLSACT: u32 = 0xffff_fff1;
const CLSACT_INGRESS: u32 = 0xffff_fff2;
const CLSACT_EGRESS: u32 = 0xffff_fff3;
const TCA_BPF_OPS_LEN: u16 = 4;
const TCA_BPF_OPS: u16 = 5;
const TCA_BPF_FLAGS: u16 = 8;
const TCA_BPF_FLAG_ACT_DIRECT: u32 = 1;
const TC_ACT_OK: u32 = 0;
const TC_ACT_SHOT: u32 = 2;

/// The guest is untrusted, and the host forwards what it sends (with a loose rp_filter, which
/// the hold needs: `TAP_ADDR`), so the tap's ingress lets through only IPv4 from `ip` and ARP
/// naming `ip` as its sender, and with an IPv6 address IPv6 from it, nothing else (no other
/// source, VLAN or other ethertype); with no `ip`, nothing. ARP is held to the address too: the
/// guest never needs another (its gateway's entry is pinned, and the host's for it is
/// permanent), and a spoofed sender could only leave stale neighbour entries; NDP is, for the
/// same reasons. A clsact qdisc (made once, kept by a create of one already there) holds a
/// classic BPF filter in direct-action mode, which a replace swaps at once, with no gap; both go
/// with the tap.
fn guard(ifindex: u32, ip: Option<VmAddr>) -> Result<()> {
    if ip.is_none() {
        let mut qdisc = tcmsg(ifindex, CLSACT_HANDLE, TC_H_CLSACT, 0);
        attr(&mut qdisc, TCA_KIND, b"clsact\0");
        netlink(libc::RTM_NEWQDISC, NLM_F_CREATE, &qdisc).map_err(|e| format!("its clsact qdisc (sch_ingress): {e}"))?;
    }
    netlink(libc::RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE, &filter_msg(ifindex, CLSACT_INGRESS, &source_filter(ip)))
        .map_err(|e| format!("its source filter (cls_bpf): {e}").into())
}

/// `ops` as the one filter at clsact's `parent` hook of the tap at `ifindex`.
fn filter_msg(ifindex: u32, parent: u32, ops: &[libc::sock_filter]) -> Vec<u8> {
    // Handle 1, priority 1, every protocol (in network order).
    let mut filter = tcmsg(ifindex, 1, parent, 1 << 16 | u32::from((libc::ETH_P_ALL as u16).to_be()));
    attr(&mut filter, TCA_KIND, b"bpf\0");
    let mut opts = Vec::new();
    attr(&mut opts, TCA_BPF_OPS_LEN, &(ops.len() as u16).to_ne_bytes());
    attr(&mut opts, TCA_BPF_OPS, &ops.iter().flat_map(|op| [&op.code.to_ne_bytes()[..], &[op.jt, op.jf], &op.k.to_ne_bytes()].concat()).collect::<Vec<u8>>());
    attr(&mut opts, TCA_BPF_FLAGS, &TCA_BPF_FLAG_ACT_DIRECT.to_ne_bytes());
    attr(&mut filter, TCA_OPTIONS, &opts);
    filter
}

/// ICMPv6 a guest never sends its host: router solicitations and advertisements, and redirects
/// (each from a link-local source, which `source_filter` drops anyway).
const ICMPV6_ROUTER: [u32; 3] = [133, 134, 137];

/// Extension headers an ICMPv6 message could follow, unread by `source_filter`, so dropped: hop-by-hop
/// options, routing and destination options. A guest has no use for them (its MLD reports, behind
/// hop-by-hop options, come from its link-local address); fragments pass, as NDP is never fragmented.
const IPV6_HIDING: [u32; 3] = [0, 43, 60];

/// The classic BPF program of `guard`, run on frames from their Ethernet header on; a load
/// past a frame's end would end it with 0 (pass), so lengths are checked first.
fn source_filter(ip: Option<VmAddr>) -> Vec<libc::sock_filter> {
    let op = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    let (ld_w, ld_h, ld_b, ld_len, jeq, jge, ret) = (0x20, 0x28, 0x30, 0x80, 0x15, 0x35, 0x06);
    let Some(VmAddr { v4, v6 }) = ip else { return vec![op(ret, 0, 0, TC_ACT_SHOT)] };
    let ip = u32::from(v4);
    // SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT: the kernel strips a VLAN tag before ingress.
    let vlan = 0xffff_f000 + 48;
    let Some(v6) = v6 else {
        // Jumps are relative to the next instruction; 13 drops, 14 passes.
        return vec![
            op(ld_w, 0, 0, vlan),       // 0
            op(jeq, 0, 11, 0),          // 1: tagged: drop
            op(ld_h, 0, 0, 12),         // 2: ethertype
            op(jeq, 0, 4, 0x0800),      // 3: not IPv4: 8
            op(ld_len, 0, 0, 0),        // 4
            op(jge, 0, 7, 14 + 20),     // 5: Ethernet and an IPv4 header
            op(ld_w, 0, 0, 14 + 12),    // 6: source
            op(jeq, 6, 5, ip),          // 7
            op(jeq, 0, 4, 0x0806),      // 8: not ARP: drop
            op(ld_len, 0, 0, 0),        // 9
            op(jge, 0, 2, 14 + 28),     // 10: Ethernet and an Ethernet/IPv4 ARP body
            op(ld_w, 0, 0, 14 + 14),    // 11: sender protocol address
            op(jeq, 1, 0, ip),          // 12
            op(ret, 0, 0, TC_ACT_SHOT), // 13
            op(ret, 0, 0, TC_ACT_OK),   // 14
        ];
    };
    // The same, then IPv6 from `v6` (its NDP too), but no router's ICMPv6 (`ICMPV6_ROUTER`), nor
    // an extension header it could hide behind (`IPV6_HIDING`); a fragment's ICMPv6 is never NDP.
    // Jumps are relative to the next instruction; 35 drops, 36 passes.
    let word = |i: usize| u32::from_be_bytes(v6.octets()[i * 4..i * 4 + 4].try_into().unwrap());
    vec![
        op(ld_w, 0, 0, vlan),            // 0
        op(jeq, 0, 33, 0),               // 1: tagged: drop
        op(ld_h, 0, 0, 12),              // 2: ethertype
        op(jeq, 0, 4, 0x0800),           // 3: not IPv4: 8
        op(ld_len, 0, 0, 0),             // 4
        op(jge, 0, 29, 14 + 20),         // 5: Ethernet and an IPv4 header
        op(ld_w, 0, 0, 14 + 12),         // 6: source
        op(jeq, 28, 27, ip),             // 7
        op(jeq, 0, 4, 0x0806),           // 8: not ARP: 13
        op(ld_len, 0, 0, 0),             // 9
        op(jge, 0, 24, 14 + 28),         // 10: Ethernet and an Ethernet/IPv4 ARP body
        op(ld_w, 0, 0, 14 + 14),         // 11: sender protocol address
        op(jeq, 23, 22, ip),             // 12
        op(jeq, 0, 21, 0x86dd),          // 13: not IPv6: drop
        op(ld_len, 0, 0, 0),             // 14
        op(jge, 0, 19, 14 + 40),         // 15: Ethernet and an IPv6 header
        op(ld_w, 0, 0, 14 + 8),          // 16: source, a word at a time
        op(jeq, 0, 17, word(0)),         // 17
        op(ld_w, 0, 0, 14 + 12),         // 18
        op(jeq, 0, 15, word(1)),         // 19
        op(ld_w, 0, 0, 14 + 16),         // 20
        op(jeq, 0, 13, word(2)),         // 21
        op(ld_w, 0, 0, 14 + 20),         // 22
        op(jeq, 0, 11, word(3)),         // 23
        op(ld_b, 0, 0, 14 + 6),          // 24: next header
        op(jeq, 3, 0, 58),               // 25: ICMPv6: 29
        op(jeq, 8, 0, IPV6_HIDING[0]),   // 26
        op(jeq, 7, 0, IPV6_HIDING[1]),   // 27
        op(jeq, 6, 7, IPV6_HIDING[2]),   // 28: anything else passes
        op(ld_len, 0, 0, 0),             // 29
        op(jge, 0, 4, 14 + 40 + 1),      // 30: and its type
        op(ld_b, 0, 0, 14 + 40),         // 31
        op(jeq, 2, 0, ICMPV6_ROUTER[0]), // 32
        op(jeq, 1, 0, ICMPV6_ROUTER[1]), // 33
        op(jeq, 0, 1, ICMPV6_ROUTER[2]), // 34
        op(ret, 0, 0, TC_ACT_SHOT),      // 35
        op(ret, 0, 0, TC_ACT_OK),        // 36
    ]
}

/// The classic BPF program of `tap_ipv6`'s egress filter: the host's IPv6 multicast to a guest
/// (MLD reports, neighbour solicitations: the host's entry for the guest is permanent) is
/// dropped, and everything else passes (as a load past a frame's end does).
fn multicast_filter() -> Vec<libc::sock_filter> {
    let op = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    let (ld_h, ld_b, jeq, ret) = (0x28, 0x30, 0x15, 0x06);
    vec![
        op(ld_h, 0, 0, 12),         // 0: ethertype
        op(jeq, 0, 3, 0x86dd),      // 1: not IPv6: pass
        op(ld_b, 0, 0, 14 + 24),    // 2: the destination's first byte
        op(jeq, 0, 1, 0xff),        // 3: multicast: drop
        op(ret, 0, 0, TC_ACT_SHOT), // 4
        op(ret, 0, 0, TC_ACT_OK),   // 5
    ]
}

/// Packets the host routes out of `tap` wait in its qdisc, in their order, until
/// `unplug_tap`; frames a packet socket sends past the qdisc (`hold::Injector`) do not.
/// Returns whether the plug may be installed, which `unplug_tap` is then due for: when it
/// is, and when the kernel's answer was lost (the change may have been made). Not when the
/// kernel refused it (no `sch_plug`, a root qdisc of another kind at 1:): then there is
/// nothing of ours to let go of, and an unplug would only cost its retries.
pub fn plug_tap(tap: &str) -> (bool, Result<()>) {
    let Ok(ifindex) = ifindex(tap) else { return (false, Err(format!("no tap {tap}").into())) };
    match request(libc::RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, &plug_msg(ifindex, TCQ_PLUG_BUFFER)) {
        Ok(()) => (true, Ok(())),
        Err(Failed::Unchanged(e)) => (false, Err(e)),
        Err(Failed::Unanswered(e)) => (true, Err(e)),
    }
}

/// Our plug at the tap's root (handle 1:, kind "plug"), and nothing else: the kernel
/// refuses the delete if the root qdisc is not that one.
fn remove_plug(ifindex: u32) -> Result<()> {
    let mut m = tcmsg(ifindex, 0x1_0000, TC_H_ROOT, 0);
    attr(&mut m, TCA_KIND, b"plug\0");
    netlink(libc::RTM_DELQDISC, 0, &m)
}

/// What waited goes out, in order, and the qdisc lets everything through from then on, a
/// FIFO: a packet arriving meanwhile queues behind the waiting ones. Failing that (tried
/// three times), the plug goes, the tap's default qdisc coming back, and what waited with
/// it; failing that too, that is retried in the background for a minute, so the tap never
/// stays plugged. Only our plug is released or removed (`remove_plug`), never another root
/// qdisc. Returns the packets the plug dropped (past `PLUG_LIMIT`, or discarded with it),
/// and whether it let them through.
///
/// Released, the plug stays the tap's root qdisc, in place of its default (fq_codel), and
/// never holds anything: tun never stops its queue, taking each packet into its ring (of
/// `TAP_QUEUE`, the tap's txqueuelen) or dropping it there (the tap's tx_dropped), so a
/// root qdisc only ever passes packets straight through, the default as well. Putting the
/// default back would cost more than it gives: any root qdisc change on a running tap
/// first points its queues at noop_qdisc for an RCU grace period (`dev_deactivate`), which
/// drops what the new route sends the VM meanwhile. The plug is put in place before the
/// route, so nothing is routed to the tap yet then.
pub fn unplug_tap(tap: &str) -> (u64, Result<()>) {
    let Ok(ifindex) = ifindex(tap) else { return (0, Err(format!("no tap {tap}").into())) };
    let stats = || qdisc_stats(ifindex, PLUG, STATS_WAIT).unwrap_or_default();
    let Err(e) = retry3(|| netlink(libc::RTM_NEWQDISC, 0, &plug_msg(ifindex, TCQ_PLUG_RELEASE_INDEFINITE))) else { return (stats().0, Ok(())) };
    let (drops, queued) = stats();
    let remove = move || remove_plug(ifindex);
    if retry3(remove).is_ok() {
        return (drops + queued, Err(format!("{e}; removed the plug instead").into()));
    }
    let retry_tap = tap.to_string();
    let retry = move || {
        let tap = retry_tap;
        let mut latest = (drops, queued);
        for _ in 0..60 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            // Only while the index is still this tap's.
            if crate::net::ifindex(&tap).ok() != Some(ifindex) {
                return;
            }
            latest = qdisc_stats(ifindex, PLUG, STATS_WAIT).unwrap_or(latest);
            if remove().is_ok() {
                return crate::log!("tap {tap}: plug removed, {} extra drops, {} queued packets discarded", latest.0.saturating_sub(drops), latest.1);
            }
        }
        crate::log!("tap {tap}: could not remove its plug, {} extra drops; backlog stays queued", latest.0.saturating_sub(drops));
    };
    if let Err(spawn) = std::thread::Builder::new().name("unplug-retry".into()).spawn(retry) {
        let removed = retry3(remove);
        return (
            drops + if removed.is_ok() { queued } else { 0 },
            Err(format!("{e}; could not start plug retry: {spawn}; inline removal: {removed:?}").into()),
        );
    }
    (drops, Err(format!("{e}; removing the plug failed too, retrying").into()))
}

/// Waits up to `wait` for what `tap`'s root qdisc still holds to reach the tap's own queue,
/// and returns how many packets it holds then (0 if it cannot say). Taking a link down resets
/// its qdisc, which frees what is there without counting it anywhere (#817).
pub fn drain_qdisc(tap: &str, wait: std::time::Duration) -> u64 {
    let Ok(ifindex) = ifindex(tap) else { return 0 };
    let end = std::time::Instant::now() + wait;
    let Ok(sock) = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket") else { return 0 };
    loop {
        // Whatever the root qdisc is (a default one, or our plug); the answer waited for only
        // within `wait` (at least a millisecond), so an unanswered query never holds it longer.
        let left = end.saturating_duration_since(std::time::Instant::now()).max(std::time::Duration::from_millis(1));
        let queued = qdisc_stats_on(&sock, ifindex, 0, left).map_or(0, |(_, queued)| queued);
        if queued == 0 || std::time::Instant::now() >= end {
            return queued;
        }
        std::thread::sleep(std::time::Duration::from_micros(200));
    }
}

fn retry3(mut f: impl FnMut() -> Result<()>) -> Result<()> {
    let mut res = Ok(());
    for _ in 0..3 {
        res = f();
        if res.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    res
}

/// Our plug's handle (1:).
const PLUG: u32 = 0x1_0000;

/// Whether our plug is `tap`'s root qdisc (released or not).
pub fn plug_is_root(tap: &str) -> bool {
    ifindex(tap).is_ok_and(|i| qdisc_stats(i, PLUG, STATS_WAIT).is_some())
}

/// How long `qdisc_stats` waits for its answer, unless told otherwise.
const STATS_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// The root qdisc's (drops, queued packets), if its handle is `handle` (0: whatever it is), from
/// RTM_GETQDISC on a socket of its own: the qdisc echoed back (NLM_F_ECHO; a get without it
/// answers nothing), no ACK, waited for up to `wait`.
fn qdisc_stats(ifindex: u32, handle: u32, wait: std::time::Duration) -> Option<(u64, u64)> {
    let sock = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket").ok()?;
    qdisc_stats_on(&sock, ifindex, handle, wait)
}

fn qdisc_stats_on(sock: &OwnedFd, ifindex: u32, handle: u32, wait: std::time::Duration) -> Option<(u64, u64)> {
    const NLM_F_ECHO: c_int = 8;
    // A zero timeval would mean no timeout at all.
    let wait = wait.max(std::time::Duration::from_micros(1));
    let timeout = libc::timeval { tv_sec: wait.as_secs() as libc::time_t, tv_usec: wait.subsec_micros() as libc::suseconds_t };
    let size = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    if unsafe { libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&timeout as *const libc::timeval).cast(), size) } != 0 {
        return None;
    }
    let body = tcmsg(ifindex, handle, TC_H_ROOT, 0);
    let mut buf = [0u8; 8192];
    let reply = exchange(sock, libc::RTM_GETQDISC, NLM_F_ECHO, &body, &mut buf).ok()?;
    if reply.len() < 36 || u16::from_ne_bytes([reply[4], reply[5]]) != libc::RTM_NEWQDISC {
        return None;
    }
    // After nlmsghdr (16) and tcmsg (20): attributes (length, type, data, padded to 4).
    let mut at = 36;
    while at + 4 <= reply.len() {
        let len = u16::from_ne_bytes([reply[at], reply[at + 1]]) as usize;
        let kind = u16::from_ne_bytes([reply[at + 2], reply[at + 3]]);
        if len < 4 || at + len > reply.len() {
            return None;
        }
        // struct tc_stats: bytes u64, packets, drops, overlimits, bps, pps, qlen, backlog (u32).
        if kind == TCA_STATS && len >= 4 + 36 {
            let u32_at = |o: usize| u64::from(u32::from_ne_bytes(reply[at + 4 + o..at + 8 + o].try_into().unwrap()));
            return Some((u32_at(12), u32_at(28)));
        }
        at += len.next_multiple_of(4);
    }
    None
}

/// struct ifinfomsg: family, pad, type, index, flags, change.
fn ifinfomsg(ifindex: u32) -> Vec<u8> {
    [&[libc::AF_UNSPEC as u8, 0, 0, 0][..], &ifindex.to_ne_bytes(), &[0; 8]].concat()
}

fn set_mac(ifindex: u32, mac: &[u8; 6]) -> Result<()> {
    let mut msg = ifinfomsg(ifindex);
    attr(&mut msg, IFLA_ADDRESS, mac);
    netlink(RTM_SETLINK, 0, &msg)
}

/// This network namespace's identity: the boot's id with the namespace's device and inode, unique on this kernel
/// while it runs. A peer sharing this host's routes has the same; an address cannot tell (a router's hairpin NAT
/// shows a peer here as the router's address, #1028).
pub fn netns_id() -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let ns = std::fs::metadata("/proc/thread-self/ns/net").ok()?;
    Some(format!("{}:{}:{}", boot.trim(), ns.dev(), ns.ino()))
}

/// Whether `ip` is one of this network namespace's addresses, IPv4 or IPv6 (an IPv4-mapped one as its IPv4).
pub fn is_local_ip(ip: IpAddr) -> Result<bool> {
    let ip = ip.to_canonical();
    Ok(ip.is_loopback() || local_ips()?.contains(&ip))
}

/// This network namespace's addresses, IPv4 and IPv6, at most a second old.
pub fn local_ips() -> Result<Vec<IpAddr>> {
    // At most a second old: listen checks one per route it installs.
    static LOCAL: std::sync::Mutex<(Option<std::time::Instant>, Vec<IpAddr>)> = std::sync::Mutex::new((None, Vec::new()));
    let mut local = LOCAL.lock().unwrap();
    if local.0.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(1)) {
        let mut addrs = std::ptr::null_mut();
        crate::syscall_check!(unsafe { libc::getifaddrs(&mut addrs) } != 0, "getifaddrs");
        local.1.clear();
        let mut current = addrs;
        while !current.is_null() {
            let addr = unsafe { &*current };
            if !addr.ifa_addr.is_null() {
                match unsafe { (*addr.ifa_addr).sa_family } as i32 {
                    libc::AF_INET => {
                        let v4 = unsafe { &*addr.ifa_addr.cast::<libc::sockaddr_in>() };
                        local.1.push(Ipv4Addr::from(v4.sin_addr.s_addr.to_ne_bytes()).into());
                    }
                    libc::AF_INET6 => {
                        let v6 = unsafe { &*addr.ifa_addr.cast::<libc::sockaddr_in6>() };
                        local.1.push(Ipv6Addr::from(v6.sin6_addr.s6_addr).into());
                    }
                    _ => {}
                }
            }
            current = addr.ifa_next;
        }
        unsafe { libc::freeifaddrs(addrs) };
        local.0 = Some(std::time::Instant::now());
    }
    Ok(local.1.clone())
}

/// The kernel's route toward `to`, as `ip route get` reads it (policy routing
/// included): its output device and the source address it would use, of `to`'s family.
pub fn route_get(to: IpAddr) -> Result<(String, IpAddr)> {
    let sock = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket")?;
    // struct rtmsg: family, dst_len (the whole address), the rest 0.
    let mut msg = match to {
        IpAddr::V4(_) => vec![libc::AF_INET as u8, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        IpAddr::V6(_) => vec![libc::AF_INET6 as u8, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };
    attr(&mut msg, RTA_DST, &octets(to));
    let mut buf = [0u8; 4096];
    let reply = exchange(&sock, libc::RTM_GETROUTE, 0, &msg, &mut buf).map_err(|_| format!("no route toward {to}: netlink failed"))?;
    route_from_reply(to, reply)
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn route_from_reply(to: IpAddr, reply: &[u8]) -> Result<(String, IpAddr)> {
    let (oif, src) = parse_route(reply).map_err(|e| format!("no route toward {to}{e}"))?;
    if src.is_ipv4() != to.is_ipv4() {
        bail!("the route toward {to}: source {src} is of the other family");
    }
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    crate::syscall_check!(unsafe { libc::if_indextoname(oif, name.as_mut_ptr()) }.is_null(), "the route toward {to}: interface {oif}");
    Ok((unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_string_lossy().into_owned(), src))
}

/// A route reply's (RTM_NEWROUTE) output interface and preferred source; else why not
/// (": " and the kernel's error, or nothing).
fn parse_route(reply: &[u8]) -> std::result::Result<(u32, IpAddr), String> {
    if reply.len() >= 20 && u16::from_ne_bytes([reply[4], reply[5]]) == NLMSG_ERROR as u16 {
        let code = i32::from_ne_bytes(reply[16..20].try_into().unwrap());
        return Err(format!(": {}", std::io::Error::from_raw_os_error(-code)));
    }
    parse_new_route(reply).ok_or_else(String::new)
}

fn parse_new_route(reply: &[u8]) -> Option<(u32, IpAddr)> {
    if reply.len() < 28 || u16::from_ne_bytes([reply[4], reply[5]]) != RTM_NEWROUTE {
        return None;
    }
    let end = (u32::from_ne_bytes(reply[..4].try_into().ok()?) as usize).min(reply.len());
    // After nlmsghdr (16) and rtmsg (12): attributes (length, type, data, padded to 4); an
    // address is 4 bytes or, in an IPv6 reply, 16.
    let (mut at, mut oif, mut src) = (28, None, None);
    while at + 4 <= end {
        let len = u16::from_ne_bytes([reply[at], reply[at + 1]]) as usize;
        if len < 4 || at + len > end {
            return None;
        }
        let data = &reply[at + 4..at + len];
        match u16::from_ne_bytes([reply[at + 2], reply[at + 3]]) {
            RTA_OIF => oif = <[u8; 4]>::try_from(data).ok().map(u32::from_ne_bytes),
            libc::RTA_PREFSRC => {
                src = match data.len() {
                    4 => <[u8; 4]>::try_from(data).ok().map(IpAddr::from),
                    16 => <[u8; 16]>::try_from(data).ok().map(IpAddr::from),
                    _ => None,
                }
            }
            _ => {}
        }
        at += len.next_multiple_of(4);
    }
    Some((oif?, src?))
}

/// Hosts sharing a netns share routes: never replace the target's tap route with one via us.
/// An IPv6 `via` (a peer with only an IPv6 underlay) is an `RTA_VIA` next hop, Linux 5.2+.
pub fn route_via(ip: Ipv4Addr, via: IpAddr) -> Result<()> {
    if is_local_ip(via)? {
        static LOGGED: std::sync::Once = std::sync::Once::new();
        LOGGED.call_once(|| crate::info!("not routing {ip} via {via}: a local address (hosts sharing a network namespace); this is logged once"));
        return Ok(());
    }
    netlink(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, &route_via_msg(ip, via)).map_err(|e| match via {
        IpAddr::V6(_) => format!("{e} (an IPv4 route via an IPv6 next hop needs Linux 5.2 or later)").into(),
        IpAddr::V4(_) => e,
    })
}

/// The attribute of a next hop of any family (`struct rtvia`: the family, then the address).
const RTA_VIA: u16 = 18;

/// `route_via`'s request: `ip`'s /32 via an IPv4 gateway (`RTA_GATEWAY`), or an IPv6 one (`RTA_VIA`).
fn route_via_msg(ip: Ipv4Addr, via: IpAddr) -> Vec<u8> {
    let mut route = rtmsg(RT_SCOPE_UNIVERSE);
    attr(&mut route, RTA_DST, &ip.octets());
    match via {
        IpAddr::V4(v4) => attr(&mut route, RTA_GATEWAY, &v4.octets()),
        IpAddr::V6(v6) => attr(&mut route, RTA_VIA, &[&(libc::AF_INET6 as u16).to_ne_bytes()[..], &v6.octets()].concat()),
    }
    route
}

/// The next hop in a route message (`struct rtmsg`, then its attributes): its `RTA_GATEWAY`, of
/// the route's family, or its `RTA_VIA`, of the family that names. None for a malformed one.
#[cfg(test)]
fn next_hop(msg: &[u8]) -> Option<IpAddr> {
    let addr = |family: c_int, data: &[u8]| match (family, data.len()) {
        (libc::AF_INET, 4) => <[u8; 4]>::try_from(data).ok().map(IpAddr::from),
        (libc::AF_INET6, 16) => <[u8; 16]>::try_from(data).ok().map(IpAddr::from),
        _ => None,
    };
    let (family, mut at, mut hop) = (c_int::from(*msg.first()?), 12, None);
    while at + 4 <= msg.len() {
        let len = u16::from_ne_bytes([msg[at], msg[at + 1]]) as usize;
        if len < 4 || at + len > msg.len() {
            return None;
        }
        let data = &msg[at + 4..at + len];
        match u16::from_ne_bytes([msg[at + 2], msg[at + 3]]) {
            RTA_GATEWAY => hop = Some(addr(family, data)?),
            RTA_VIA if data.len() >= 2 => hop = Some(addr(u16::from_ne_bytes([data[0], data[1]]).into(), &data[2..])?),
            RTA_VIA => return None,
            _ => {}
        }
        at += len.next_multiple_of(4);
    }
    hop
}

/// The next hops in `table` (`/proc/net/route`: hex, in network byte order).
pub fn gateways(table: &str) -> Vec<Ipv4Addr> {
    let hop = |l: &str| u32::from_str_radix(l.split_whitespace().nth(2)?, 16).ok().filter(|&g| g != 0);
    table.lines().skip(1).filter_map(hop).map(|g| Ipv4Addr::from(g.to_ne_bytes())).collect()
}

/// The next hops in `table` (`/proc/net/ipv6_route`: each address 32 hex digits, in network byte order).
pub fn gateways6(table: &str) -> Vec<Ipv6Addr> {
    let hop = |l: &str| u128::from_str_radix(l.split_whitespace().nth(4)?, 16).ok().filter(|&g| g != 0);
    table.lines().filter_map(hop).map(Ipv6Addr::from).collect()
}

/// This network namespace's next hops, IPv4 and IPv6 (none of IPv6 where it is off: no
/// `/proc/net/ipv6_route`).
pub fn next_hops() -> std::io::Result<Vec<IpAddr>> {
    let v4 = gateways(&std::fs::read_to_string("/proc/net/route")?).into_iter().map(IpAddr::V4);
    let v6 = match std::fs::read_to_string("/proc/net/ipv6_route") {
        Ok(table) => gateways6(&table),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    Ok(v4.chain(v6.into_iter().map(IpAddr::V6)).collect())
}

/// A delete names the device, so it removes only that route. Its IPv6 address's /128 goes with
/// the /32: added first, so a failure leaves the /32 where it was routed; deleted after it, even
/// when the /32's delete fails.
pub fn route_dev(add: bool, ip: VmAddr, ifindex: u32) -> Result<()> {
    if add {
        let v6 = ip.v6.map_or(Ok(()), |v6| netlink(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, &dev_route_msg(v6.into(), ifindex)));
        return v6.and_then(|()| netlink(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, &dev_route_msg(ip.v4.into(), ifindex)));
    }
    ip.each().map(|dst| unroute_dev(dst, ifindex)).fold(Ok(()), Result::and)
}

/// Deletes `ip`'s route (a /32 or /128) to the device at `ifindex`, and no other.
pub fn unroute_dev(ip: IpAddr, ifindex: u32) -> Result<()> {
    netlink(RTM_DELROUTE, 0, &dev_route_msg(ip, ifindex))
}

/// The route of `ip` (a /32 or /128) to the device at `ifindex`.
fn dev_route_msg(ip: IpAddr, ifindex: u32) -> Vec<u8> {
    let (mut route, dst) = match ip {
        IpAddr::V4(v4) => (rtmsg(RT_SCOPE_LINK), v4.octets().to_vec()),
        IpAddr::V6(v6) => (rtmsg6(RT_SCOPE_LINK), v6.octets().to_vec()),
    };
    attr(&mut route, RTA_DST, &dst);
    attr(&mut route, RTA_OIF, &ifindex.to_ne_bytes());
    route
}

/// Removes `ip`'s route through a gateway (`route_via`'s, whichever peer it names: a migration's
/// switch to its target is never recorded, and a record can name a newer peer than the route):
/// universe scope only, so never a tap's or the hold device's (`route_dev`, link scope), which
/// hosts sharing a network namespace each keep for their own VMs. Its IPv6 address's /128 via a
/// peer (`route_via6`) goes with it.
pub fn unroute(ip: VmAddr) {
    let mut route = rtmsg(RT_SCOPE_UNIVERSE);
    attr(&mut route, RTA_DST, &ip.v4.octets());
    let _ = netlink(RTM_DELROUTE, 0, &route);
    if let Some(v6) = ip.v6 {
        unroute6(v6);
    }
}

/// The protocol of a /128 routed via a peer (`route_via6`): IPv6 route deletes go by no scope, so
/// `unroute6` names it, and takes no tap's or hold device's /128 (`RTPROT_STATIC`, `route_dev`).
const RTPROT_PEER6: u8 = libc::RTPROT_BOOT;

/// A VM's IPv6 address (`vm_ipv6_prefix`) routed via a peer's IPv6 underlay, as `route_via` routes
/// its /32: never via a local address (hosts sharing a network namespace).
pub fn route_via6(ip: Ipv6Addr, via: Ipv6Addr) -> Result<()> {
    if is_local_ip(via.into())? {
        return Ok(());
    }
    netlink(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, &via6_msg(ip, Some(via)))
}

/// Removes `ip`'s /128 via a peer (`route_via6`'s, whichever peer), and no other.
pub fn unroute6(ip: Ipv6Addr) {
    let _ = netlink(RTM_DELROUTE, 0, &via6_msg(ip, None));
}

/// `ip`'s /128 of `RTPROT_PEER6`, via `via` if given.
fn via6_msg(ip: Ipv6Addr, via: Option<Ipv6Addr>) -> Vec<u8> {
    let mut route = rtmsg6(RT_SCOPE_UNIVERSE);
    route[5] = RTPROT_PEER6;
    attr(&mut route, RTA_DST, &ip.octets());
    if let Some(via) = via {
        attr(&mut route, RTA_GATEWAY, &via.octets());
    }
    route
}

fn rtmsg(scope: u8) -> Vec<u8> {
    vec![libc::AF_INET as u8, 32, 0, 0, RT_TABLE_MAIN, RTPROT_STATIC, scope, RTN_UNICAST, 0, 0, 0, 0]
}

/// `rtmsg` for an IPv6 /128.
fn rtmsg6(scope: u8) -> Vec<u8> {
    vec![libc::AF_INET6 as u8, 128, 0, 0, RT_TABLE_MAIN, RTPROT_STATIC, scope, RTN_UNICAST, 0, 0, 0, 0]
}

fn attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
    buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

/// Whether a failed request left things unchanged or its answer was lost (the change may have been made).
enum Failed {
    Unchanged(crate::util::Error),
    Unanswered(crate::util::Error),
}

fn netlink(kind: u16, flags: c_int, body: &[u8]) -> Result<()> {
    request(kind, flags, body).map_err(|(Failed::Unchanged(e) | Failed::Unanswered(e))| e)
}

thread_local!(static FD: std::cell::Cell<Option<OwnedFd>> = const { std::cell::Cell::new(None) });

/// Opens this thread's netlink socket now, if it has none: before a lock its first request is made under.
pub fn ready() {
    if let Some(sock) = FD.take().or_else(|| socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket").ok()) {
        FD.set(Some(sock));
    }
}

/// One socket per thread, so each recv is the ACK of the request just sent and a slow one
/// (a tap's teardown) holds up no other thread; any failure drops it, so no stale ACK is
/// left for the next.
fn request(kind: u16, flags: c_int, body: &[u8]) -> std::result::Result<(), Failed> {
    let sock = FD.take().map_or_else(|| socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket"), Ok).map_err(Failed::Unchanged)?;
    let mut ack = [0u8; 1024];
    let reply = exchange(&sock, kind, flags | NLM_F_ACK, body, &mut ack)?;
    if reply.len() < 20 {
        return Err(Failed::Unanswered(format!("netlink: short reply ({} bytes)", reply.len()).into()));
    }
    FD.set(Some(sock));
    let kind = u16::from_ne_bytes([ack[4], ack[5]]);
    let code = i32::from_ne_bytes(ack[16..20].try_into().unwrap());
    if kind == NLMSG_ERROR as u16 && code != 0 {
        return Err(Failed::Unchanged(format!("netlink: {}", std::io::Error::from_raw_os_error(-code)).into()));
    }
    Ok(())
}

fn exchange<'a>(sock: &OwnedFd, kind: u16, flags: c_int, body: &[u8], buf: &'a mut [u8]) -> std::result::Result<&'a [u8], Failed> {
    let flags = ((flags | NLM_F_REQUEST) as u16).to_ne_bytes();
    // struct nlmsghdr: length, type, flags, seq, pid.
    let msg = [&((16 + body.len()) as u32).to_ne_bytes()[..], &kind.to_ne_bytes(), &flags, &[1, 0, 0, 0, 0, 0, 0, 0], body].concat();
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    if send_to(sock, &msg, &addr) < 0 {
        return Err(Failed::Unchanged(format!("netlink: {}", std::io::Error::last_os_error()).into()));
    }
    let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        return Err(Failed::Unanswered(format!("netlink: {}", std::io::Error::last_os_error()).into()));
    }
    Ok(&buf[..n as usize])
}

pub fn ifindex(dev: &str) -> Result<u32> {
    let name = std::ffi::CString::new(dev)?;
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => bail!("no interface {dev}"),
        i => Ok(i),
    }
}

pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    for (m, part) in mac.iter_mut().zip(s.trim().split(':')) {
        *m = u8::from_str_radix(part, 16)?;
    }
    Ok(mac)
}

/// Whether `dev` is an Ethernet link (ARPHRD_ETHER), one that takes ARP announcements.
pub fn is_ethernet(dev: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{dev}/type")).is_ok_and(|t| t.trim() == "1")
}

/// `/proc/sys/net/{family}/conf/{dev}/{key}`, by its path: a sysctl key's dots would split a
/// device name with one (`eth0.100`, a `--prefix` with a dot).
pub fn conf(family: &str, dev: &str, key: &str, value: &str) -> Result<()> {
    std::fs::write(format!("/proc/sys/net/{family}/conf/{dev}/{key}"), value).map_err(|e| format!("{family} {key} of {dev}: {e}"))?;
    Ok(())
}

/// How long a failed proxy ARP setup waits before it is tried again.
const PROXY_ARP_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

type ProxyArp = std::collections::BTreeMap<String, std::result::Result<u32, std::time::Instant>>;

/// Proxy ARP on an announce device, once per interface (a derived one follows the routes; one
/// recreated under its name gets it again). A failure is warned of once and an error until it
/// is tried again, after `PROXY_ARP_RETRY`.
pub fn proxy_arp(dev: &str) -> Result<()> {
    static ON: std::sync::Mutex<ProxyArp> = std::sync::Mutex::new(ProxyArp::new());
    enable_proxy_arp(&mut ON.lock().unwrap(), dev, ifindex(dev), || conf("ipv4", dev, "proxy_arp", "1"))
}

fn enable_proxy_arp(on: &mut ProxyArp, dev: &str, index: Result<u32>, write: impl FnOnce() -> Result<()>) -> Result<()> {
    match (on.get(dev), &index) {
        (Some(Ok(was)), Ok(now)) if was == now => return Ok(()),
        (Some(Err(at)), _) if at.elapsed() < PROXY_ARP_RETRY => bail!("proxy ARP on {dev} failed; tried again shortly"),
        _ => {}
    }
    match index.and_then(|i| write().map(|()| i)) {
        Ok(i) => {
            on.insert(dev.into(), Ok(i));
            Ok(())
        }
        Err(e) => {
            if !matches!(on.insert(dev.into(), Err(std::time::Instant::now())), Some(Err(_))) {
                crate::log!("WARNING: proxy ARP on {dev}: {e}");
            }
            Err(e)
        }
    }
}

pub fn ip_forward() -> Result<()> {
    enable("/proc/sys/net/ipv4/ip_forward".as_ref()).map_err(|e| format!("ip_forward: {e}").into())
}

/// IPv6 forwarding (`all`), for VMs' IPv6 addresses (`vm_ipv6_prefix`). An interface that
/// forwards takes router advertisements only with accept_ra 2, so turning it on would leave each
/// with 1 (the default) without them: an uplink configured by them (SLAAC, its default route)
/// would lose that as it expires. Each that takes them now is set to 2 first, and logged; once
/// forwarding is on (by this or anyone), interfaces' accept_ra is left to their admin.
pub fn ipv6_forward() -> Result<()> {
    ipv6_forward_in("/proc/sys/net/ipv6".as_ref()).map_err(|e| format!("IPv6 forwarding: {e}").into())
}

fn ipv6_forward_in(root: &std::path::Path) -> std::io::Result<()> {
    let all = root.join("conf/all/forwarding");
    if std::fs::read_to_string(&all).is_ok_and(|v| v.trim() == "1") {
        return Ok(());
    }
    for dev in std::fs::read_dir(root.join("conf"))? {
        let dev = dev?;
        let name = dev.file_name().to_string_lossy().into_owned();
        let is = |key: &str, value: &str| std::fs::read_to_string(dev.path().join(key)).is_ok_and(|v| v.trim() == value);
        // Not lo's, nor a device's with IPv6 off (a VM's tap until it has an IPv6 address).
        if ["all", "default", "lo"].contains(&name.as_str()) || is("disable_ipv6", "1") || !is("accept_ra", "1") || is("forwarding", "1") {
            continue;
        }
        match std::fs::write(dev.path().join("accept_ra"), "2") {
            Ok(()) => crate::log!("IPv6 forwarding (vm_ipv6_prefix): {name} still takes router advertisements (accept_ra 2)"),
            // Gone meanwhile (a tap removed).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                crate::log!("WARNING: IPv6 forwarding (vm_ipv6_prefix): {name} stops taking router advertisements: setting its accept_ra to 2 failed: {e}")
            }
        }
    }
    std::fs::write(all, "1")
}

/// Sets a boolean sysctl to 1, written only if it is not already: one already on is enough even
/// where it is read-only (a container's /proc/sys).
fn enable(path: &std::path::Path) -> std::io::Result<()> {
    if std::fs::read_to_string(path).is_ok_and(|v| v.trim() == "1") {
        return Ok(());
    }
    std::fs::write(path, "1")
}

pub fn gratuitous_arp(dev: &str, ip: Ipv4Addr) -> Result<()> {
    let ifindex = ifindex(dev)?;
    let mac = parse_mac(&std::fs::read_to_string(format!("/sys/class/net/{dev}/address"))?)?;
    let fd = socket(libc::AF_PACKET, libc::SOCK_RAW, 0x0806u16.to_be() as i32, "packet socket")?;
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&[0x08, 0x06]); // ARP
    frame.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]); // ethernet/ipv4, request
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&ip.octets());
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&ip.octets());
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
    addr.sll_ifindex = ifindex as i32;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    crate::syscall_check!(send_to(&fd, &frame, &addr) < 0, "send gratuitous arp");
    Ok(())
}

/// `a.b.c.d/len` or `first-last`.
#[derive(Debug, Clone)]
pub struct IpRange {
    first: u32,
    last: u32,
}

impl std::fmt::Display for IpRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}-{}", Ipv4Addr::from(self.first), Ipv4Addr::from(self.last))
    }
}

impl IpRange {
    pub fn parse(s: &str) -> Result<IpRange> {
        if let Some((a, b)) = s.split_once('-') {
            let (first, last) = (u32::from(a.parse::<Ipv4Addr>()?), u32::from(b.parse::<Ipv4Addr>()?));
            if first > last {
                bail!("empty address range {s}");
            }
            return Ok(IpRange { first, last });
        }
        let (net, len) = s.split_once('/').ok_or_else(|| format!("bad address range {s:?}"))?;
        let len: u32 = len.parse()?;
        if !(1..=30).contains(&len) {
            bail!("prefix length must be 1..30 in {s}");
        }
        let mask = u32::MAX << (32 - len);
        let base = u32::from(net.parse::<Ipv4Addr>()?) & mask;
        Ok(IpRange { first: base + 1, last: (base | !mask) - 1 })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (self.first..=self.last).contains(&u32::from(ip))
    }

    pub fn contains_range(&self, other: &IpRange) -> bool {
        self.first <= other.first && other.last <= self.last
    }

    /// In it, and never with a 16-bit half all zeros or all ones: checksum completion could
    /// rewrite one into the other and leave the IP header checksum valid (#365), forging a source.
    pub fn allocatable(&self, ip: Ipv4Addr) -> bool {
        let n = u32::from(ip);
        self.contains(ip) && [n >> 16, n & 0xffff].iter().all(|h| ![0, 0xffff].contains(h))
    }

    /// The first address not `taken`, looking from `hint` (if in range) to the
    /// end, then from the start: each address at most once.
    pub fn allocate(&self, hint: Option<Ipv4Addr>, taken: impl Fn(Ipv4Addr) -> bool) -> Option<Ipv4Addr> {
        let start = hint.map(u32::from).filter(|h| (self.first..=self.last).contains(h)).unwrap_or(self.first);
        (start..=self.last).chain(self.first..start).map(Ipv4Addr::from).find(|ip| self.allocatable(*ip) && !taken(*ip))
    }

    /// The address after `ip`, wrapping around.
    pub fn after(&self, ip: Ipv4Addr) -> Ipv4Addr {
        let n = u32::from(ip);
        Ipv4Addr::from(if n >= self.last || n < self.first { self.first } else { n + 1 })
    }
}

/// `vm_ipv6_prefix` (#1296): a /96 whose low 32 bits are a VM's IPv4 address. Only a /96: a
/// shorter prefix would leave bits between it and the IPv4 address that no VM tells apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Prefix(std::net::Ipv6Addr);

/// Ranges a VM's IPv6 address must never be in, each as (first address, prefix length, what).
const NOT_VM_IPV6: [(std::net::Ipv6Addr, u32, &str); 6] = [
    (std::net::Ipv6Addr::UNSPECIFIED, 96, "unspecified, loopback or IPv4-compatible"),
    (std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96, "IPv4-mapped"),
    (std::net::Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0, 0), 96, "IPv4-translated"),
    (std::net::Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 32, "NAT64"),
    (std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10, "link-local"),
    (std::net::Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8, "multicast"),
];

impl Ipv6Prefix {
    /// `ADDR/96`, its low 32 bits zero; never one a VM's address must not be in (`NOT_VM_IPV6`).
    pub fn parse(s: &str) -> Result<Ipv6Prefix> {
        let (net, len) = s.split_once('/').ok_or_else(|| format!("bad vm_ipv6_prefix {s:?}: give an IPv6 /96, as fd00:0:0:1::/96"))?;
        let net: std::net::Ipv6Addr = net.parse().map_err(|_| format!("bad vm_ipv6_prefix {s:?}: {net:?} is not an IPv6 address"))?;
        if len != "96" {
            bail!("bad vm_ipv6_prefix {s:?}: the prefix length must be 96, the IPv4 address filling the other 32 bits");
        }
        if u128::from(net) as u32 != 0 {
            bail!("bad vm_ipv6_prefix {s:?}: its last 32 bits must be zero (they are each VM's IPv4 address)");
        }
        if let Some((_, _, what)) = NOT_VM_IPV6.iter().find(|(first, len, _)| u128::from(net) >> (128 - len) == u128::from(*first) >> (128 - len)) {
            bail!("bad vm_ipv6_prefix {s:?}: {what} addresses are never a VM's");
        }
        Ok(Ipv6Prefix(net))
    }

    /// The VM IPv6 address for `ip`: this prefix, with `ip` in the low 32 bits. Only local
    /// configuration says it: a peer is told and tells IPv4 addresses alone.
    pub fn vm(&self, ip: Ipv4Addr) -> std::net::Ipv6Addr {
        (u128::from(self.0) | u128::from(u32::from(ip))).into()
    }

    /// Whether `ip` is in this /96, and the IPv4 address it would be a VM's.
    pub fn ipv4_of(&self, ip: std::net::Ipv6Addr) -> Option<Ipv4Addr> {
        let n = u128::from(ip);
        (n >> 32 == u128::from(self.0) >> 32).then(|| Ipv4Addr::from(n as u32))
    }
}

impl std::fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/96", self.0)
    }
}

impl serde::Serialize for Ipv6Prefix {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Ipv6Prefix {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ipv6Prefix::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names_keep_the_old_name_then_claim_free_suffixes() {
        for name in ["f12345x3fffff", "f123453fffffh"] {
            let mut live = std::collections::HashSet::new();
            let mut allocate =
                || free_name(name, |dev| if live.insert(dev.to_string()) { Ok(()) } else { Err(std::io::Error::from_raw_os_error(libc::EBUSY)) }).unwrap();
            assert_eq!(allocate(), name);
            for n in 0..256 {
                let dev = allocate();
                assert_eq!(dev, format!("{name}{n:x}"));
                assert!(dev.len() < libc::IFNAMSIZ);
            }
            let error = free_name(name, |_| Err(std::io::Error::from_raw_os_error(libc::EEXIST))).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("no free device names"));
            live.remove(&format!("{name}80"));
            assert_eq!(
                free_name(name, |dev| {
                    if live.contains(dev) {
                        Err(std::io::Error::from_raw_os_error(libc::EBUSY))
                    } else {
                        Ok(())
                    }
                })
                .unwrap(),
                format!("{name}80")
            );
        }
    }

    #[test]
    fn device_names_retry_only_collisions_and_refuse_truncation() {
        for errno in [libc::EPERM, libc::ENOENT, libc::EINVAL, libc::EIO] {
            let mut calls = 0;
            let error = free_name("f123451h", |_| {
                calls += 1;
                Err(std::io::Error::from_raw_os_error(errno))
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
            assert_eq!(calls, 1);
        }
        let error = free_name("0123456789abcdef", |_| panic!("overlong name claimed")).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        // A short name stops at the suffix bound, not only at IFNAMSIZ.
        let mut calls = 0;
        let error = free_name("f12345x1", |_| {
            calls += 1;
            Err(std::io::Error::from_raw_os_error(libc::EEXIST))
        })
        .unwrap_err();
        assert_eq!((error.kind(), calls), (std::io::ErrorKind::InvalidInput, 1 + NAME_SUFFIXES));
        assert!(error.to_string().contains("no free device names"), "{error}");
    }

    #[test]
    fn tap_queue_drains_nonblocking_frames_and_stops_at_empty() {
        use std::os::unix::net::UnixDatagram;

        let (read, write) = UnixDatagram::pair().unwrap();
        let fd: OwnedFd = read.into();
        for nonblocking in [false, true] {
            if nonblocking {
                assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) }, 0);
            }
            write.send(b"first").unwrap();
            write.send(b"second").unwrap();
            let mut frames = Vec::new();
            assert_eq!(read_tap_queue(&fd, &mut |f| frames.push(f.to_vec())), 2);
            assert_eq!(frames, [b"first".to_vec(), b"second".to_vec()]);
            assert_eq!(read_tap_queue(&fd, &mut |_| panic!("empty")), 0);
        }
        write.send(b"ongoing").unwrap();
        assert_eq!(
            read_tap_queue(&fd, &mut |_| {
                write.send(b"ongoing").unwrap();
            }),
            u64::from(TAP_QUEUE)
        );
    }

    #[test]
    fn proxy_arp_retries_failures_after_a_pause_and_recreated_interfaces() {
        let mut on = ProxyArp::new();
        let writes = std::cell::Cell::new(0);
        let write = || {
            writes.set(writes.get() + 1);
            Ok(())
        };
        let expire = |on: &mut ProxyArp| on.insert("eth0".into(), Err(std::time::Instant::now() - PROXY_ARP_RETRY));
        assert!(enable_proxy_arp(&mut on, "eth0", Err("missing".into()), write).is_err());
        assert!(enable_proxy_arp(&mut on, "eth0", Ok(1), write).is_err(), "a failure waits before it is tried again");
        assert_eq!(writes.get(), 0);
        expire(&mut on);
        assert!(enable_proxy_arp(&mut on, "eth0", Ok(1), || Err("write failed".into())).is_err());
        expire(&mut on);
        enable_proxy_arp(&mut on, "eth0", Ok(1), write).unwrap();
        enable_proxy_arp(&mut on, "eth0", Ok(1), write).unwrap();
        assert_eq!(writes.get(), 1, "success alone skips a write");
        enable_proxy_arp(&mut on, "eth0", Ok(2), write).unwrap();
        assert_eq!(writes.get(), 2, "the same name with a new index needs setup");
    }

    #[test]
    fn a_vm_ipv6_address_is_the_prefix_and_its_ipv4_address() {
        let p = Ipv6Prefix::parse("fd00:0:0:1:0:0::/96").unwrap();
        assert_eq!(p.to_string(), "fd00:0:0:1::/96");
        assert_eq!(p.vm("10.200.0.7".parse().unwrap()), "fd00:0:0:1::ac8:7".parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(p.ipv4_of("fd00:0:0:1::ac8:7".parse().unwrap()), Some("10.200.0.7".parse().unwrap()));
        assert_eq!(p.ipv4_of("fd00:0:0:2::ac8:7".parse().unwrap()), None);
        assert_eq!(serde_json::to_value(p).unwrap(), "fd00:0:0:1::/96");
        assert_eq!(
            serde_json::from_value::<Ipv6Prefix>(serde_json::json!("2001:db8::/96")).unwrap().vm(Ipv4Addr::new(192, 0, 2, 1)).to_string(),
            "2001:db8::c000:201"
        );
        for (bad, why) in [
            ("fd00::", "give an IPv6 /96"),
            ("10.0.0.0/96", "not an IPv6 address"),
            ("fd00::/64", "must be 96"),
            ("fd00::/97", "must be 96"),
            ("fd00::1/96", "last 32 bits"),
            ("::/96", "loopback"),
            ("::ffff:0:0/96", "IPv4-mapped"),
            ("::ffff:0:0:0/96", "IPv4-translated"),
            ("64:ff9b::/96", "NAT64"),
            ("64:ff9b:1::/96", "NAT64"),
            ("fe80::/96", "link-local"),
            ("febf:1::/96", "link-local"),
            ("ff02::/96", "multicast"),
        ] {
            let e = Ipv6Prefix::parse(bad).unwrap_err().to_string();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn allocation_starts_at_the_hint_and_wraps() {
        let r = IpRange::parse("10.9.0.1-10.9.0.4").unwrap();
        let ip = |n: u8| Ipv4Addr::new(10, 9, 0, n);
        let probe = |hint: Option<u8>, used: &[u8]| {
            let probed = std::cell::RefCell::new(Vec::new());
            let got = r.allocate(hint.map(ip), |a| {
                probed.borrow_mut().push(a.octets()[3]);
                used.contains(&a.octets()[3])
            });
            (got.map(|a| a.octets()[3]), probed.into_inner())
        };
        assert_eq!(probe(None, &[]), (Some(1), vec![1]));
        assert_eq!(probe(Some(3), &[]), (Some(3), vec![3]), "no rescan from the start");
        assert_eq!(probe(Some(3), &[3, 4]), (Some(1), vec![3, 4, 1]), "wraps around");
        assert_eq!(probe(Some(2), &[1, 2, 3, 4]), (None, vec![2, 3, 4, 1]), "each address once");
        assert_eq!(probe(Some(9), &[]), (Some(1), vec![1]), "a hint out of range starts at the start");
        assert_eq!((r.after(ip(2)), r.after(ip(4)), r.after(ip(9))), (ip(3), ip(1), ip(1)));
    }

    #[test]
    fn no_address_has_a_half_of_all_zeros_or_ones() {
        let r = IpRange::parse("10.9.255.254-10.10.0.2").unwrap();
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert!(r.allocatable(ip("10.9.255.254")) && r.allocatable(ip("10.10.0.1")));
        assert!(!r.allocatable(ip("10.9.255.255")) && !r.allocatable(ip("10.10.0.0")));
        assert!(r.contains(ip("10.9.255.255")) && r.contains(ip("10.10.0.0")), "still in it: a home address");
        let mut got = Vec::new();
        while let Some(a) = r.allocate(None, |a| got.contains(&a)) {
            got.push(a);
        }
        assert_eq!(got, [ip("10.9.255.254"), ip("10.10.0.1"), ip("10.10.0.2")]);
    }

    #[test]
    fn gateways_are_read_off_the_route_table() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
                     eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(gateways(table), [Ipv4Addr::new(192, 168, 1, 1)]);
        // An unreachable route and a link's own prefix have none.
        let table6 = "fd7a115ca1e000000000000000000000 30 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001 tailscale0\n\
                      00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n\
                      00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n";
        assert_eq!(gateways6(table6), ["fe80::1".parse::<Ipv6Addr>().unwrap()]);
    }

    #[test]
    fn a_route_reply_gives_its_device_and_source() {
        let reply = |kind: u16, attrs: &[(u16, &[u8])]| reply_of(libc::AF_INET as u8, kind, attrs);
        let (dst, src, gw) = ([100u8, 64, 0, 7], [100u8, 101, 9, 2], [192u8, 168, 1, 1]);
        let full = reply(
            RTM_NEWROUTE,
            &[(RTA_DST, &dst), (libc::RTA_TABLE, &52u32.to_ne_bytes()), (libc::RTA_PREFSRC, &src), (RTA_GATEWAY, &gw), (RTA_OIF, &9u32.to_ne_bytes())],
        );
        assert_eq!(parse_route(&full), Ok((9, Ipv4Addr::from(src).into())));
        // Trailing bytes past the message are not read as attributes.
        assert_eq!(parse_route(&[&full[..], &[8, 0, 4, 0, 1, 0, 0, 0]].concat()), Ok((9, Ipv4Addr::from(src).into())));
        assert_eq!(parse_route(&reply(RTM_NEWROUTE, &[(RTA_OIF, &9u32.to_ne_bytes())])), Err("".into()), "no source");
        assert_eq!(parse_route(&reply(RTM_NEWROUTE, &[(libc::RTA_PREFSRC, &src)])), Err("".into()), "no device");
        // An error gives the kernel's errno (struct nlmsgerr: a negative errno after the header).
        let mut err = reply(NLMSG_ERROR as u16, &[]);
        err[16..20].copy_from_slice(&(-libc::ENETUNREACH).to_ne_bytes());
        let why = std::io::Error::from_raw_os_error(libc::ENETUNREACH).to_string();
        assert_eq!(parse_route(&err), Err(format!(": {why}")));
        assert_eq!(parse_route(&err[..19]), Err("".into()), "a short error");
        let mut bad = full.clone();
        bad[28] = 200;
        assert_eq!(parse_route(&bad), Err("".into()), "an attribute past the end");
    }

    /// An `nlmsghdr` of `kind` and a `struct rtmsg` of `family`, then `attrs`.
    fn reply_of(family: u8, kind: u16, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; 16];
        m[4..6].copy_from_slice(&kind.to_ne_bytes());
        let dst_len = if family == libc::AF_INET6 as u8 { 128 } else { 32 };
        m.extend_from_slice(&[family, dst_len, 0, 0, 254, 2, 0, 1, 0, 0, 0, 0]);
        for (k, d) in attrs {
            attr(&mut m, *k, d);
        }
        let len = m.len() as u32;
        m[..4].copy_from_slice(&len.to_ne_bytes());
        m
    }

    #[test]
    fn an_ipv6_route_reply_gives_its_device_and_source() {
        let reply = |attrs: &[(u16, &[u8])]| reply_of(libc::AF_INET6 as u8, RTM_NEWROUTE, attrs);
        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap().octets();
        let (dst, src, gw) = (v6("2001:db8:1::7"), v6("2001:db8:2::2"), v6("fe80::1"));
        // 16-byte addresses before and after the device, among RTA_PREF's one byte and RTA_CACHEINFO's 32.
        let full = reply(&[
            (RTA_DST, &dst),
            (libc::RTA_TABLE, &254u32.to_ne_bytes()),
            (libc::RTA_PREFSRC, &src),
            (libc::RTA_PREF, &[0]),
            (RTA_GATEWAY, &gw),
            (RTA_OIF, &3u32.to_ne_bytes()),
            (libc::RTA_CACHEINFO, &[0; 32]),
        ]);
        assert_eq!(parse_route(&full), Ok((3, IpAddr::from(src))));
        assert_eq!(parse_route(&reply(&[(RTA_OIF, &3u32.to_ne_bytes())])), Err("".into()), "no source");
        assert_eq!(parse_route(&reply(&[(RTA_OIF, &3u32.to_ne_bytes()), (libc::RTA_PREFSRC, &src[..8])])), Err("".into()), "a source of 8 bytes");
        // A source of the other family is never taken as the route's.
        let mixed = reply_of(libc::AF_INET as u8, RTM_NEWROUTE, &[(libc::RTA_PREFSRC, &src), (RTA_OIF, &1u32.to_ne_bytes())]);
        let err = route_from_reply(Ipv4Addr::new(192, 0, 2, 1).into(), &mixed).unwrap_err().to_string();
        assert!(err.contains("of the other family"), "{err}");
    }

    #[test]
    fn route_lookup_errors_and_vanished_interfaces_are_reported() {
        let to = Ipv4Addr::new(192, 0, 2, 1).into();
        let err = route_from_reply(to, &[]).unwrap_err().to_string();
        assert!(err.contains("no route toward 192.0.2.1"), "{err}");
        let mut reply = vec![0u8; 28];
        reply[4..6].copy_from_slice(&RTM_NEWROUTE.to_ne_bytes());
        attr(&mut reply, RTA_OIF, &u32::MAX.to_ne_bytes());
        attr(&mut reply, libc::RTA_PREFSRC, &[192, 0, 2, 2]);
        let len = reply.len() as u32;
        reply[..4].copy_from_slice(&len.to_ne_bytes());
        let err = route_from_reply(to, &reply).unwrap_err().to_string();
        assert!(err.contains("route toward 192.0.2.1: interface 4294967295:"), "{err}");
    }

    #[test]
    fn the_kernel_names_the_route_toward_loopback() {
        let (dev, src) = route_get(Ipv4Addr::LOCALHOST.into()).unwrap();
        assert!(!dev.is_empty() && src == Ipv4Addr::LOCALHOST, "{dev} {src}");
        // And over IPv6, where the host has it (`ipv6.disable=1` leaves no ::1).
        if local_ips().unwrap().contains(&Ipv6Addr::LOCALHOST.into()) {
            let (dev, src) = route_get(Ipv6Addr::LOCALHOST.into()).unwrap();
            assert!(!dev.is_empty() && src == Ipv6Addr::LOCALHOST, "{dev} {src}");
        }
        // Loopback (ARPHRD_LOOPBACK) takes no ARP announcements, nor does a device that is not there.
        assert!(!is_ethernet("lo") && !is_ethernet("flexvm-none0"));
    }

    #[test]
    fn long_interface_names_are_refused() {
        assert!(ifreq("fvci0A3fffffhff").is_ok(), "15 bytes");
        // Refused before /dev/net/tun is opened (no CAP_NET_ADMIN needed).
        let e = create_tap("fvci0A3fffffta00", "").unwrap_err().to_string();
        assert!(e.contains("over 15 bytes"), "{e}");
    }

    /// Needs root: `sudo cargo test -- --ignored`. A tap names its owner; a plug the kernel
    /// refuses is told apart (nothing to unplug), and only our plug is ever removed.
    #[test]
    #[ignore]
    fn taps_name_their_owner_and_only_our_plug_goes() {
        let _root = crate::test_util::root_net_lock();
        let tap = format!("tw4p{:x}", std::process::id());
        let tc = |args: &str| std::process::Command::new("tc").args(args.split(' ')).output().unwrap();
        let root = || String::from_utf8_lossy(&tc(&format!("qdisc show dev {tap} root")).stdout).into_owned();
        struct TapGuard<'a>(&'a str);
        impl Drop for TapGuard<'_> {
            fn drop(&mut self) {
                delete_tap(self.0);
            }
        }
        create_tap(&tap, "flexvm 1 2 /run/x").unwrap();
        let _tap = TapGuard(&tap);
        let alias = std::fs::read_to_string(format!("/sys/class/net/{tap}/ifalias")).unwrap();
        assert_eq!(alias.trim_end(), "flexvm 1 2 /run/x");
        assert!(tc(&format!("qdisc add dev {tap} root handle 1: fq_codel")).status.success());
        let (plugged, res) = plug_tap(&tap);
        assert!(!plugged && res.is_err(), "another kind at 1: refuses the plug");
        assert!(remove_plug(ifindex(&tap).unwrap()).is_err());
        assert!(root().contains("fq_codel 1:"), "{}", root());
        assert!(tc(&format!("qdisc del dev {tap} root")).status.success());
        let (plugged, res) = plug_tap(&tap);
        assert!(plugged && res.is_ok(), "{res:?}");
        assert!(root().contains("plug 1:"), "{}", root());
        let (drops, res) = unplug_tap(&tap);
        assert!(drops == 0 && res.is_ok(), "{res:?}");
        remove_plug(ifindex(&tap).unwrap()).unwrap();
        assert!(!root().contains("plug"), "{}", root());
        // Shut from the start; an address, then another, replaces its one filter.
        let filters = || String::from_utf8_lossy(&tc(&format!("filter show dev {tap} ingress")).stdout).into_owned();
        assert!(filters().matches("direct-action").count() == 1 && filters().contains("bytecode '1,6 0 0 2'"), "{}", filters());
        for ip in [Ipv4Addr::new(192, 0, 2, 7), Ipv4Addr::new(192, 0, 2, 8)] {
            neighbour(ip.into(), &tap).unwrap();
            let f = filters();
            assert!(f.matches("direct-action").count() == 1 && f.contains(&format!(" {},", u32::from(ip))), "{f}");
        }
    }

    /// Needs CAP_NET_ADMIN; no VM. An old owner must not delete a replacement tap.
    #[test]
    #[ignore]
    fn deleting_an_old_tap_preserves_a_reused_name() {
        let _root = crate::test_util::root_net_lock();
        let tap = format!("tw4r{:x}", std::process::id());
        let create = || create_indexed_tap("test", |fd| claim_tap(fd, &tap).map(|()| tap.clone()).map_err(Into::into)).unwrap().1;
        let old = create();
        delete_link(old, &tap);
        let new = create();
        delete_link(old, &tap);
        let retained = ifindex(&tap).ok();
        delete_link(new, &tap);
        assert_ne!(old, new);
        assert_eq!(retained, Some(new));
    }

    /// A message as udev broadcasts it on its monitor group (`udev_event`).
    fn udev_message(props: &[&str]) -> Vec<u8> {
        let props: Vec<u8> = props.iter().flat_map(|p| [p.as_bytes(), b"\0"].concat()).collect();
        let words = [40u32, 40, props.len() as u32, 0, 0, 0, 0].map(u32::to_ne_bytes).concat();
        [&b"libudev\0"[..], &0xfeedcafe_u32.to_be_bytes(), &words, &props].concat()
    }

    #[test]
    fn udev_events_name_their_action_and_interface() {
        let msg = udev_message(&["ACTION=add", "DEVPATH=/devices/virtual/net/fx0t0", "SUBSYSTEM=net", "INTERFACE=fx0t0", "IFINDEX=4242", "SEQNUM=9"]);
        assert_eq!(udev_event(&msg), Some((&b"add"[..], 4242)));
        assert_eq!(udev_event(&udev_message(&["ACTION=remove", "IFINDEX=7"])), Some((&b"remove"[..], 7)));
        // Not a network device's, the kernel's own format, a bad magic, properties past the end.
        assert_eq!(udev_event(&udev_message(&["ACTION=add", "DEVNAME=/dev/kvm"])), None);
        assert_eq!(udev_event(b"add@/devices/virtual/net/fx0t0\0ACTION=add\0IFINDEX=4242\0"), None);
        let mut bad = msg.clone();
        bad[8] ^= 1;
        assert_eq!(udev_event(&bad), None);
        assert_eq!(udev_event(&msg[..msg.len() - 3]), None);
        assert_eq!(udev_event(&msg[..20]), None);
    }

    /// Needs root: `sudo cargo test -- --ignored`. udev's late write of a MAC of its own (#841) is
    /// undone once udev says it is done with the tap, not before, and not for another device's
    /// event; the MAC is checked meanwhile, and the watcher ends with its tap.
    #[test]
    #[ignore]
    fn udevs_late_mac_is_undone_once_udev_is_done() {
        use std::time::{Duration, Instant};
        let _root = crate::test_util::root_net_lock();
        let tap = format!("tw4u{:x}", std::process::id());
        struct TapGuard<'a>(&'a str);
        impl Drop for TapGuard<'_> {
            fn drop(&mut self) {
                delete_tap(self.0);
            }
        }
        // Made with no watcher of its own; a udevd here is done with it before the test goes on.
        make_tap("test", None, |fd| claim_tap(fd, &tap).map(|()| tap.clone()).map_err(Into::into)).unwrap();
        let _tap = TapGuard(&tap);
        let _ = std::process::Command::new("udevadm").args(["settle", "--timeout=10"]).status();
        let index = ifindex(&tap).unwrap();
        set_mac(index, &GATEWAY_MAC).unwrap();
        let mac = || parse_mac(&std::fs::read_to_string(format!("/sys/class/net/{tap}/address")).unwrap()).unwrap();
        let udev = uevent_socket(UDEV_GROUP).expect("a socket on udev's group");
        let ours = [0x72, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sender = socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_KOBJECT_UEVENT, "uevent socket").unwrap();
        let send = |props: &[&str]| {
            let mut to: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            (to.nl_family, to.nl_groups) = (libc::AF_NETLINK as u16, UDEV_GROUP);
            assert!(send_to(&sender, &udev_message(props), &to) > 0, "{}", std::io::Error::last_os_error());
        };
        let (on, other) = (format!("IFINDEX={index}"), format!("IFINDEX={}", index + 1000));
        // Detached, so a failed assertion leaves it behind rather than joining a watcher that never ends.
        let udev = std::sync::Arc::new(udev);
        let watch = |recheck| {
            let (udev, tap) = (udev.clone(), tap.clone());
            std::thread::spawn(move || keep_mac_from_udev(&udev, index, &tap, recheck))
        };
        let ends = |w: &std::thread::JoinHandle<()>| {
            let by = Instant::now() + Duration::from_secs(10);
            while !w.is_finished() && Instant::now() < by {
                std::thread::sleep(Duration::from_millis(10));
            }
            w.is_finished()
        };
        set_mac(index, &ours).unwrap();
        let start = Instant::now();
        let w = watch(Duration::from_secs(60));
        send(&["ACTION=add", "SUBSYSTEM=net", &other]);
        send(&["ACTION=change", "SUBSYSTEM=net", &on]);
        std::thread::sleep(Duration::from_millis(300));
        assert!(!w.is_finished() && mac() == ours, "another device's event, or a change, is not udev done with this tap");
        send(&["ACTION=add", "SUBSYSTEM=net", &format!("INTERFACE={tap}"), &on]);
        assert!(ends(&w) && mac() == GATEWAY_MAC && start.elapsed() < Duration::from_secs(10), "by the event, not a recheck: {:?}", start.elapsed());
        // With no event, a recheck puts it back, however busy udev is with other devices, and the
        // watcher goes on until udev's remove.
        set_mac(index, &ours).unwrap();
        let w = watch(Duration::from_millis(200));
        let back = Instant::now() + Duration::from_secs(5);
        while mac() != GATEWAY_MAC && Instant::now() < back {
            send(&["ACTION=change", "SUBSYSTEM=net", &other]);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(mac(), GATEWAY_MAC);
        assert!(!w.is_finished());
        send(&["ACTION=remove", "SUBSYSTEM=net", &on]);
        assert!(ends(&w));
        // A tap gone ends its watcher at the next recheck, touching no other device.
        assert!(!restore_mac(index, "flexvm-none0"));
        let w = watch(Duration::from_millis(50));
        delete_tap(&tap);
        assert!(ends(&w));
    }

    /// A classic BPF program's verdict on `frame` (with a VLAN tag stripped or not), by an
    /// interpreter of the instructions `source_filter` and `multicast_filter` use, a load past
    /// the end returning 0 as the kernel's.
    fn run(prog: &[libc::sock_filter], frame: &[u8], tagged: bool) -> u32 {
        let (mut a, mut pc) = (0u32, 0usize);
        loop {
            let op = &prog[pc];
            pc += 1;
            let jump = |taken: bool| if taken { op.jt as usize } else { op.jf as usize };
            match op.code {
                0x20 if op.k == 0xffff_f030 => a = tagged as u32,
                0x20 | 0x28 | 0x30 => {
                    let n = match op.code {
                        0x20 => 4,
                        0x28 => 2,
                        _ => 1,
                    };
                    let Some(b) = frame.get(op.k as usize..op.k as usize + n) else { return 0 };
                    a = b.iter().fold(0, |a, &b| a << 8 | u32::from(b));
                }
                0x80 => a = frame.len() as u32,
                0x15 => pc += jump(a == op.k),
                0x35 => pc += jump(a >= op.k),
                0x06 => return op.k,
                c => panic!("unexpected op {c:#x}"),
            }
        }
    }

    /// `source_filter`'s verdict on `frame`.
    fn verdict(ip: Option<VmAddr>, frame: &[u8], tagged: bool) -> u32 {
        run(&source_filter(ip), frame, tagged)
    }

    /// An Ethernet frame's header, guest to gateway, of type `ty`.
    fn eth(ty: u16) -> Vec<u8> {
        [&GATEWAY_MAC[..], &GUEST_MAC, &ty.to_be_bytes()].concat()
    }

    /// A frame of an IPv6 packet from `src` to `dst`, its next header `next` and `payload` after.
    fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Vec<u8> {
        [&eth(0x86dd)[..], &[0x60, 0, 0, 0], &(payload.len() as u16).to_be_bytes(), &[next, 64], &src.octets(), &dst.octets(), payload].concat()
    }

    fn six(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn taps_pass_only_their_own_address() {
        let (me, other) = (Ipv4Addr::new(10, 9, 0, 2), Ipv4Addr::new(10, 9, 0, 3));
        let ipv4 = |src: Ipv4Addr| [&eth(0x0800)[..], &[0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0], &src.octets(), &[10, 9, 0, 9], &[0; 8]].concat();
        let arp = |sender: Ipv4Addr| [&eth(0x0806)[..], &[0, 1, 8, 0, 6, 4, 0, 1], &GUEST_MAC, &sender.octets(), &[0; 6], &[169, 254, 1, 1]].concat();
        // IPv4 and ARP go by the IPv4 address alone, with an IPv6 address or without.
        let with_v6 = |v4: Ipv4Addr| VmAddr { v4, v6: Some(Ipv6Prefix::parse("fd00:7::/96").unwrap().vm(v4)) };
        for (me, other) in [(VmAddr::from(me), VmAddr::from(other)), (with_v6(me), with_v6(other))] {
            let pass = |ip: VmAddr, frame: &[u8]| verdict(Some(ip), frame, false) == TC_ACT_OK;
            let (v4, other4) = (me.v4, other.v4);
            assert!(pass(me, &ipv4(v4)));
            assert!(!pass(me, &ipv4(other4)), "another's source");
            assert!(!pass(other, &ipv4(v4)), "an old address, once readdressed");
            assert!(!pass(me, &ipv4(Ipv4Addr::UNSPECIFIED)), "a DHCP client's");
            assert!(pass(me, &arp(v4)));
            assert!(!pass(me, &arp(other4)), "ARP with another's sender");
            assert!(!pass(me, &ipv4(v4)[..33]), "short of an IPv4 header");
            assert!(!pass(me, &arp(v4)[..41]), "short of an ARP body");
            assert!(!pass(me, &eth(0x0800)), "an Ethernet header alone");
            assert!(!pass(me, &[&eth(0x88cc)[..], &[0; 40]].concat()), "another ethertype");
            assert!(verdict(Some(me), &ipv4(v4), true) == TC_ACT_SHOT, "VLAN tagged");
        }
        let v6 = Ipv6Prefix::parse("fd00:7::/96").unwrap().vm(me);
        assert!(verdict(Some(me.into()), &ipv6(v6, six("2001:db8::1"), 17, &[0; 8]), false) == TC_ACT_SHOT, "IPv6, with no IPv6 address");
        assert!(verdict(Some(me.into()), &[&eth(0x86dd)[..], &[0; 40]].concat(), false) == TC_ACT_SHOT, "IPv6 from ::");
        assert!(verdict(None, &ipv4(me), false) == TC_ACT_SHOT && verdict(None, &arp(me), false) == TC_ACT_SHOT, "a tap with no address yet");
    }

    #[test]
    fn taps_pass_ipv6_only_from_their_own_ipv6_address() {
        let (v6, other, there) = (six("fd00:7::a09:2"), six("fd00:7::a09:3"), six("2001:db8::1"));
        let me = VmAddr { v4: Ipv4Addr::new(10, 9, 0, 2), v6: Some(v6) };
        let pass = |frame: &[u8]| verdict(Some(me), frame, false) == TC_ACT_OK;
        let udp = [0u8; 8];
        assert!(pass(&ipv6(v6, there, 17, &udp)));
        assert!(pass(&ipv6(v6, there, 6, &[0; 20])), "TCP");
        assert!(pass(&ipv6(v6, there, 59, &[])), "no next header, nothing after the header");
        // Echo, and NDP from its address (its gateway's entry is pinned, but a guest may still solicit).
        for ty in [128, 129, 135, 136] {
            assert!(pass(&ipv6(v6, TAP_ADDR6, 58, &[ty, 0, 0, 0])), "ICMPv6 {ty}");
        }
        for ty in ICMPV6_ROUTER {
            assert!(!pass(&ipv6(v6, six("ff02::2"), 58, &[ty as u8, 0, 0, 0])), "a router's ICMPv6 {ty}");
        }
        assert!(!pass(&ipv6(v6, TAP_ADDR6, 58, &[])), "ICMPv6 short of its type");
        for next in IPV6_HIDING {
            assert!(!pass(&ipv6(v6, six("ff02::2"), next as u8, &[58, 0, 0, 0, 0, 0, 0, 0, 134, 0, 0, 0])), "a router advertisement behind header {next}");
        }
        assert!(pass(&ipv6(v6, there, 44, &[17, 0, 0, 1, 0, 0, 0, 1])), "a fragment");
        assert!(!pass(&ipv6(other, there, 17, &udp)), "another's source");
        for i in 0..16 {
            let mut src = v6.octets();
            src[i] ^= 1;
            assert!(!pass(&ipv6(src.into(), there, 17, &udp)), "another source, differing in byte {i}");
        }
        assert!(!pass(&ipv6(six("::ffff:10.9.0.2"), there, 17, &udp)), "its IPv4 address, mapped");
        assert!(!pass(&ipv6(six("fe80::400:acff:fe10:2"), TAP_ADDR6, 58, &[135, 0, 0, 0])), "NDP from a link-local address");
        let mld = [58, 0, 5, 2, 0, 0, 1, 0, 143, 0, 0, 0];
        assert!(!pass(&ipv6(Ipv6Addr::UNSPECIFIED, six("ff02::16"), 0, &mld)), "an MLD report from ::");
        assert!(!pass(&ipv6(v6, there, 17, &udp)[..14 + 39]), "short of an IPv6 header");
        assert!(!pass(&eth(0x86dd)), "an Ethernet header alone");
        assert!(verdict(Some(me), &ipv6(v6, there, 17, &udp), true) == TC_ACT_SHOT, "VLAN tagged");
        let readdressed = VmAddr { v4: Ipv4Addr::new(10, 9, 0, 3), v6: Some(other) };
        assert!(verdict(Some(readdressed), &ipv6(v6, there, 17, &udp), false) == TC_ACT_SHOT, "an old address, once readdressed");
        assert!(verdict(None, &ipv6(v6, there, 17, &udp), false) == TC_ACT_SHOT, "a tap with no address yet");
    }

    #[test]
    fn taps_drop_the_hosts_ipv6_multicast_on_the_way_out() {
        let out = |frame: &[u8]| run(&multicast_filter(), frame, false) == TC_ACT_OK;
        let (v6, there) = (six("fd00:7::a09:2"), six("2001:db8::1"));
        let mld = [58, 0, 5, 2, 0, 0, 1, 0, 143, 0, 0, 0];
        assert!(!out(&ipv6(TAP_ADDR6, six("ff02::16"), 0, &mld)), "an MLDv2 report");
        assert!(!out(&ipv6(TAP_ADDR6, six("ff02::1:ff0a:902"), 58, &[135, 0, 0, 0])), "a neighbour solicitation");
        assert!(out(&ipv6(there, v6, 17, &[0; 8])), "unicast to the guest");
        assert!(out(&ipv6(TAP_ADDR6, v6, 58, &[129, 0, 0, 0])), "the gateway's echo reply");
        assert!(out(&[&eth(0x0800)[..], &[0x45, 0, 0, 20], &[0; 16]].concat()) && out(&eth(0x0806)), "IPv4 and ARP");
        assert!(out(&eth(0x86dd)), "short: no destination to tell by");
    }

    /// Without an IPv6 address a tap is guarded, neighboured and routed as it was before
    /// `vm_ipv6_prefix`: the same filter and messages, and no others.
    #[test]
    fn without_an_ipv6_address_a_tap_is_set_up_as_before() {
        let v4 = Ipv4Addr::new(10, 9, 0, 2);
        let ip = u32::from(v4);
        let before: [(u16, u8, u8, u32); 15] = [
            (0x20, 0, 0, 0xffff_f030),
            (0x15, 0, 11, 0),
            (0x28, 0, 0, 12),
            (0x15, 0, 4, 0x0800),
            (0x80, 0, 0, 0),
            (0x35, 0, 7, 34),
            (0x20, 0, 0, 26),
            (0x15, 6, 5, ip),
            (0x15, 0, 4, 0x0806),
            (0x80, 0, 0, 0),
            (0x35, 0, 2, 42),
            (0x20, 0, 0, 28),
            (0x15, 1, 0, ip),
            (0x06, 0, 0, TC_ACT_SHOT),
            (0x06, 0, 0, TC_ACT_OK),
        ];
        let ops = |ip| source_filter(ip).iter().map(|op| (op.code, op.jt, op.jf, op.k)).collect::<Vec<_>>();
        assert_eq!(ops(Some(v4.into())), before);
        assert_eq!(ops(None), [(0x06, 0, 0, TC_ACT_SHOT)]);
        assert_eq!(VmAddr::from(v4).each().collect::<Vec<_>>(), [IpAddr::V4(v4)], "one neighbour entry, one route");
        let mut neigh = [&[libc::AF_INET as u8, 0, 0, 0][..], &7u32.to_ne_bytes(), &NUD_PERMANENT.to_ne_bytes(), &[0, 0]].concat();
        attr(&mut neigh, NDA_DST, &v4.octets());
        attr(&mut neigh, NDA_LLADDR, &GUEST_MAC);
        assert_eq!(neigh_msg(7, v4.into()), neigh);
        let mut route = vec![libc::AF_INET as u8, 32, 0, 0, RT_TABLE_MAIN, RTPROT_STATIC, RT_SCOPE_LINK, RTN_UNICAST, 0, 0, 0, 0];
        attr(&mut route, RTA_DST, &v4.octets());
        attr(&mut route, RTA_OIF, &7u32.to_ne_bytes());
        assert_eq!(dev_route_msg(v4.into(), 7), route);
    }

    #[test]
    fn an_ipv6_address_gets_its_own_neighbour_entry_and_route() {
        let (v4, v6) = (Ipv4Addr::new(10, 9, 0, 2), six("fd00:7::a09:2"));
        let both = VmAddr { v4, v6: Some(v6) };
        assert_eq!(both.each().collect::<Vec<_>>(), [IpAddr::V4(v4), IpAddr::V6(v6)]);
        let neigh = neigh_msg(7, v6.into());
        assert_eq!(neigh[..12], [&[libc::AF_INET6 as u8, 0, 0, 0][..], &7u32.to_ne_bytes(), &NUD_PERMANENT.to_ne_bytes(), &[0, 0]].concat());
        assert_eq!(
            neigh[12..],
            [&20u16.to_ne_bytes()[..], &NDA_DST.to_ne_bytes(), &v6.octets(), &10u16.to_ne_bytes(), &NDA_LLADDR.to_ne_bytes(), &GUEST_MAC, &[0, 0]].concat()
        );
        let route = dev_route_msg(v6.into(), 7);
        assert_eq!(route[..12], [libc::AF_INET6 as u8, 128, 0, 0, RT_TABLE_MAIN, RTPROT_STATIC, RT_SCOPE_LINK, RTN_UNICAST, 0, 0, 0, 0]);
        assert_eq!(
            route[12..],
            [&20u16.to_ne_bytes()[..], &RTA_DST.to_ne_bytes(), &v6.octets(), &8u16.to_ne_bytes(), &RTA_OIF.to_ne_bytes(), &7u32.to_ne_bytes()].concat()
        );
        // The gateway: link-local, no duplicate address detection.
        let addr = tap_addr6_msg(7);
        assert_eq!(addr[..8], [&[libc::AF_INET6 as u8, 64, IFA_F_NODAD, RT_SCOPE_LINK][..], &7u32.to_ne_bytes()].concat());
        assert_eq!(addr[8..], [&20u16.to_ne_bytes()[..], &IFA_ADDRESS.to_ne_bytes(), &TAP_ADDR6.octets()].concat());
    }

    /// Forwarding stops interfaces with accept_ra 1 taking router advertisements: those that take
    /// them are set to 2 first, and no other; once it is on, nothing is touched.
    #[test]
    fn ipv6_forwarding_keeps_router_advertisements_coming() {
        let d = crate::test_util::TempDir::new("ipv6-forward");
        let conf = |dev: &str, key: &str| d.join(format!("conf/{dev}/{key}"));
        let set = |dev: &str, keys: &[(&str, &str)]| {
            std::fs::create_dir_all(d.join(format!("conf/{dev}"))).unwrap();
            for (k, v) in keys {
                std::fs::write(conf(dev, k), format!("{v}\n")).unwrap();
            }
        };
        let off = [("disable_ipv6", "0"), ("forwarding", "0")];
        for dev in ["all", "default", "lo", "eth0"] {
            set(dev, &[off[0], off[1], ("accept_ra", "1")]);
        }
        set("wlan0", &[off[0], off[1], ("accept_ra", "0")]);
        set("fx0t1", &[("disable_ipv6", "1"), off[1], ("accept_ra", "1")]);
        set("br0", &[off[0], ("forwarding", "1"), ("accept_ra", "1")]);
        let ra = |dev: &str| std::fs::read_to_string(conf(dev, "accept_ra")).unwrap().trim().to_string();
        ipv6_forward_in(&d).unwrap();
        assert_eq!(std::fs::read_to_string(conf("all", "forwarding")).unwrap().trim(), "1");
        assert_eq!(ra("eth0"), "2", "took them: still does");
        for (dev, was) in [("default", "1"), ("lo", "1"), ("wlan0", "0"), ("fx0t1", "1"), ("br0", "1")] {
            assert_eq!(ra(dev), was, "{dev} is left as it was");
        }
        set("eth1", &[off[0], off[1], ("accept_ra", "1")]);
        ipv6_forward_in(&d).unwrap();
        assert_eq!(ra("eth1"), "1", "forwarding on already: its admin's");
    }

    #[test]
    fn macs_print_as_firecracker_takes_them() {
        assert_eq!(mac_string(&GUEST_MAC), "06:00:ac:10:00:02");
        assert_eq!(parse_mac(&mac_string(&GATEWAY_MAC)).unwrap(), GATEWAY_MAC);
    }

    #[test]
    fn loopback_routes_are_noops() {
        let loopback: [IpAddr; 4] =
            [Ipv4Addr::LOCALHOST.into(), Ipv4Addr::new(127, 42, 3, 4).into(), Ipv4Addr::new(127, 255, 255, 255).into(), Ipv6Addr::LOCALHOST.into()];
        for via in loopback {
            // Works without CAP_NET_ADMIN: no route request is sent.
            route_via(Ipv4Addr::new(192, 0, 2, 123), via).unwrap();
        }
    }

    /// #1295: a VM's /32 via an IPv4 next hop is an `RTA_GATEWAY`; via an IPv6 one, an `RTA_VIA`
    /// (`struct rtvia`: AF_INET6, then the address), padded to 4 bytes.
    #[test]
    fn route_messages_name_next_hops_of_either_family() {
        let ip = Ipv4Addr::new(192, 0, 2, 123);
        let rta = |len: u16, kind: u16| [len.to_ne_bytes(), kind.to_ne_bytes()].concat();
        let head = [libc::AF_INET as u8, 32, 0, 0, RT_TABLE_MAIN, RTPROT_STATIC, RT_SCOPE_UNIVERSE, RTN_UNICAST, 0, 0, 0, 0];
        let dst = [&rta(8, RTA_DST)[..], &[192, 0, 2, 123]].concat();
        let v4 = Ipv4Addr::new(192, 0, 2, 1);
        let gateway = route_via_msg(ip, v4.into());
        assert_eq!(gateway, [&head[..], &dst, &rta(8, RTA_GATEWAY), &v4.octets()].concat());
        let v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let via = route_via_msg(ip, v6.into());
        assert_eq!(via, [&head[..], &dst, &rta(22, RTA_VIA), &(libc::AF_INET6 as u16).to_ne_bytes(), &v6.octets(), &[0, 0]].concat());
        assert_eq!(via.len() % 4, 0);
        // Parsed back, and as the kernel may send them: an RTA_VIA of an IPv4 address, among other attributes.
        assert_eq!(next_hop(&gateway), Some(v4.into()));
        assert_eq!(next_hop(&via), Some(v6.into()));
        let mut other = head.to_vec();
        attr(&mut other, libc::RTA_TABLE, &254u32.to_ne_bytes());
        attr(&mut other, RTA_VIA, &[&(libc::AF_INET as u16).to_ne_bytes()[..], &v4.octets()].concat());
        attr(&mut other, RTA_OIF, &3u32.to_ne_bytes());
        assert_eq!(next_hop(&other), Some(v4.into()));
        // None: no next hop, or a malformed one.
        assert_eq!(next_hop(&[&head[..], &dst].concat()), None);
        let bad = |data: &[u8]| {
            let mut m = head.to_vec();
            attr(&mut m, RTA_VIA, data);
            next_hop(&m)
        };
        assert_eq!(bad(&[10]), None, "no whole family");
        assert_eq!(bad(&[&(libc::AF_INET6 as u16).to_ne_bytes()[..], &v4.octets()].concat()), None, "an IPv6 family, 4 bytes");
        assert_eq!(bad(&[&(libc::AF_PACKET as u16).to_ne_bytes()[..], &[0; 6]].concat()), None, "another family");
        assert_eq!(next_hop(&via[..via.len() - 4]), None, "cut short");
        let mut gw6 = vec![libc::AF_INET6 as u8, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        attr(&mut gw6, RTA_GATEWAY, &v6.octets());
        assert_eq!(next_hop(&gw6), Some(v6.into()), "an IPv6 route's gateway");
    }

    #[test]
    fn a_failed_local_address_check_stops_routing() {
        const CHILD: &str = "FLEXVM_TEST_GETIFADDRS_FAILURE";
        if std::env::var_os(CHILD).is_some() {
            // A fresh process has no cached addresses; no spare fd makes getifaddrs fail.
            let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
            let e = route_via(Ipv4Addr::new(198, 51, 100, 7), Ipv4Addr::new(192, 0, 2, 1).into()).unwrap_err().to_string();
            assert!(e.contains("getifaddrs"), "{e}");
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "net::tests::a_failed_local_address_check_stops_routing", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn interface_indices_must_still_have_the_expected_name() {
        let index = ifindex("lo").unwrap();
        assert!(has_name(index, "lo"));
        assert!(!has_name(index, "flexvm-none0"));
        assert!(!has_name(0, "lo"));
    }

    /// Needs CAP_SYS_ADMIN and CAP_NET_ADMIN, and iproute2; no VM. Routes stay in a private netns.
    #[test]
    #[ignore]
    fn withdrawals_remove_only_gateway_routes() {
        std::thread::spawn(|| {
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0, "{}", std::io::Error::last_os_error());
            let ip = |args: &[&str]| {
                let out = std::process::Command::new("ip").args(args).output().unwrap();
                assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
                String::from_utf8(out.stdout).unwrap()
            };
            ip(&["link", "add", "peer0", "type", "dummy"]);
            ip(&["addr", "add", "192.0.2.3/24", "dev", "peer0"]);
            ip(&["link", "set", "peer0", "up"]);
            let index = ifindex("peer0").unwrap();
            let target = Ipv4Addr::new(198, 51, 100, 7);
            let route = || ip(&["-4", "route", "show", "198.51.100.7/32"]);
            route_dev(true, target.into(), index).unwrap();
            unroute(target.into());
            assert!(route().contains("dev peer0"), "a tap route survives a withdrawal");
            route_via(target, Ipv4Addr::new(192, 0, 2, 2).into()).unwrap();
            unroute(target.into());
            assert!(route().is_empty(), "a route via any peer goes");
            // Via an IPv6 next hop (RTA_VIA, Linux 5.2+), and withdrawn the same way (#1295).
            ip(&["-6", "addr", "add", "2001:db8::3/64", "dev", "peer0", "nodad"]);
            route_via(target, "2001:db8::2".parse().unwrap()).unwrap();
            assert!(route().contains("via inet6 2001:db8::2 dev peer0"), "{}", route());
            unroute(target.into());
            assert!(route().is_empty(), "a route via an IPv6 peer goes");
            // A VM's /128 via a peer goes with its /32, a tap's (`route_dev`) stays (#1297).
            let v6: Ipv6Addr = "fd00:7::c633:6407".parse().unwrap();
            let route6 = || ip(&["-6", "route", "show", "fd00:7::c633:6407/128"]);
            let both = VmAddr { v4: target, v6: Some(v6) };
            route_dev(true, both, index).unwrap();
            unroute(both);
            assert!(route6().contains("dev peer0") && !route6().contains("via"), "a tap's /128 survives a withdrawal: {}", route6());
            route_via6(v6, "2001:db8::2".parse().unwrap()).unwrap();
            assert!(route6().contains("via 2001:db8::2 dev peer0"), "{}", route6());
            unroute(both);
            assert!(route6().is_empty(), "a /128 via a peer goes: {}", route6());
        })
        .join()
        .unwrap();
    }

    /// Needs CAP_SYS_ADMIN and CAP_NET_ADMIN, and iproute2; no VM. In a private netns: a tap has
    /// IPv6 off until an address with an IPv6 one is its, then the /128's neighbour entry, route
    /// and gateway beside the /32's, back after the tap goes down and up, and gone with the route.
    #[test]
    #[ignore]
    fn a_taps_ipv6_comes_with_an_ipv6_address() {
        std::thread::spawn(|| {
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0, "{}", std::io::Error::last_os_error());
            let ip = |args: &[&str]| {
                let out = std::process::Command::new("ip").args(args).output().unwrap();
                assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
                String::from_utf8(out.stdout).unwrap()
            };
            let tap = "tw6t0";
            create_tap(tap, "test").unwrap();
            let index = ifindex(tap).unwrap();
            let sysctl = |key: &str| std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{tap}/{key}")).unwrap().trim().to_string();
            let v4 = Ipv4Addr::new(10, 9, 0, 2);
            let v6 = six("fd00:7::a09:2");
            attach(v4.into(), tap).unwrap();
            assert_eq!(sysctl("disable_ipv6"), "1", "no IPv6 address: IPv6 stays off");
            assert!(ip(&["-6", "route", "show", "table", "all", "dev", tap]).is_empty());
            let both = VmAddr { v4, v6: Some(v6) };
            attach(both, tap).unwrap();
            let check = || {
                assert_eq!((sysctl("disable_ipv6"), sysctl("addr_gen_mode"), sysctl("accept_ra")), ("0".into(), "1".into(), "0".into()));
                let addrs = ip(&["-6", "addr", "show", "dev", tap]);
                assert!(addrs.contains("inet6 fe80::1/64 scope link nodad") && addrs.matches("inet6").count() == 1, "{addrs}");
                let neigh = ip(&["-6", "neigh", "show", "dev", tap]);
                assert!(neigh.contains(&format!("{v6} lladdr {} PERMANENT", mac_string(&GUEST_MAC))), "{neigh}");
                assert!(ip(&["-6", "route", "show", &format!("{v6}/128")]).contains(&format!("dev {tap}")));
                assert!(ip(&["-4", "route", "show", "10.9.0.2/32"]).contains(&format!("dev {tap}")));
            };
            check();
            assert_eq!(std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").unwrap().trim(), "1");
            let tc = std::process::Command::new("tc").args(["filter", "show", "dev", tap, "egress"]).output().unwrap();
            assert!(String::from_utf8_lossy(&tc.stdout).contains("direct-action"), "the multicast filter");
            set_link_up(tap, false).unwrap();
            set_link_up(tap, true).unwrap();
            attach(both, tap).unwrap();
            check();
            // Held, both go to the hold device, and come back with an attach.
            let hold = crate::hold::Holder::new("tw6h").unwrap().unwrap();
            hold.hold(both, 1).unwrap();
            assert_eq!(std::fs::read_to_string("/proc/sys/net/ipv6/conf/tw6h/disable_ipv6").unwrap().trim(), "0");
            assert!(ip(&["-6", "route", "show", &format!("{v6}/128")]).contains("dev tw6h"));
            assert!(ip(&["-4", "route", "show", "10.9.0.2/32"]).contains("dev tw6h"));
            hold.forget(v4, 1);
            assert!(ip(&["-6", "route", "show", "dev", "tw6h"]).is_empty() && ip(&["-4", "route", "show", "dev", "tw6h"]).is_empty());
            attach(both, tap).unwrap();
            check();
            route_dev(false, both, index).unwrap();
            assert!(ip(&["-6", "route", "show", &format!("{v6}/128")]).is_empty() && ip(&["-4", "route", "show", "10.9.0.2/32"]).is_empty());
            delete_tap(tap);
        })
        .join()
        .unwrap();
    }

    /// An already enabled sysctl needs no write, so a read-only one that is on is no failure.
    #[test]
    fn a_sysctl_already_on_is_not_written() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::test_util::TempDir::new("sysctl");
        let (on, off) = (d.join("on"), d.join("off"));
        for (p, v) in [(&on, "1\n"), (&off, "0\n")] {
            std::fs::write(p, v).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        assert!(enable(&on).is_ok());
        if unsafe { libc::geteuid() } != 0 {
            assert!(enable(&off).is_err(), "off and read-only: a failure");
        }
        let w = d.join("w");
        std::fs::write(&w, "0").unwrap();
        enable(&w).unwrap();
        assert_eq!(std::fs::read_to_string(&w).unwrap(), "1");
    }
}
