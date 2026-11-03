//! Guest networking via ioctls and rtnetlink, so images need no iproute2. All but the VM's own
//! addresses is set up at template boot: eth0 talks to a fixed link-local gateway whose MAC is pinned
//! by a static ARP entry, and for IPv6 by a permanent neighbour entry (every host tap has that MAC,
//! so it survives migration).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::os;

pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);
/// The IPv6 gateway: the host's taps' link-local address, also at GATEWAY_MAC.
pub const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
pub const GATEWAY_MAC: [u8; 6] = [0x06, 0x00, 0xa9, 0xfe, 0x01, 0x01];
const IFACE: &str = "eth0";

struct Sock(std::os::fd::OwnedFd);

impl Sock {
    fn ioctl<T>(&self, req: libc::c_ulong, arg: &mut T) -> io::Result<()> {
        os(unsafe { libc::ioctl(std::os::fd::AsRawFd::as_raw_fd(&self.0), req as _, arg as *mut T) }).map(drop)
    }
}

fn sockaddr(ip: Ipv4Addr) -> libc::sockaddr {
    // struct sockaddr_in: family, port, address.
    let mut sa_data = [0; 14];
    sa_data[2..6].copy_from_slice(&ip.octets().map(|b| b as libc::c_char));
    libc::sockaddr { sa_family: libc::AF_INET as _, sa_data }
}

fn name<const N: usize>(dst: &mut [libc::c_char; N], name: &str) {
    for (d, s) in dst.iter_mut().zip(name.bytes()) {
        *d = s as libc::c_char;
    }
}

fn ifreq(iface: &str) -> libc::ifreq {
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    name(&mut req.ifr_name, iface);
    req
}

fn link_up(s: &Sock, iface: &str) -> io::Result<()> {
    let mut req = ifreq(iface);
    s.ioctl(libc::SIOCGIFFLAGS, &mut req)?;
    unsafe { req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
    s.ioctl(libc::SIOCSIFFLAGS, &mut req)
}

fn add_route(s: &Sock, dst: Ipv4Addr, mask: Ipv4Addr, gw: Option<Ipv4Addr>) -> io::Result<()> {
    let mut dev = *b"eth0\0";
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    (rt.rt_dst, rt.rt_genmask, rt.rt_flags) = (sockaddr(dst), sockaddr(mask), libc::RTF_UP);
    if mask == Ipv4Addr::BROADCAST {
        rt.rt_flags |= libc::RTF_HOST;
    }
    if let Some(gw) = gw {
        rt.rt_gateway = sockaddr(gw);
        rt.rt_flags |= libc::RTF_GATEWAY;
    }
    rt.rt_dev = dev.as_mut_ptr().cast();
    match s.ioctl(libc::SIOCADDRT, &mut rt) {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        r => r,
    }
}

static NETLINK: OnceLock<(libc::c_int, u32)> = OnceLock::new();
/// Why eth0 has no IPv6 (a kernel without it), which a request for an IPv6 address is told.
static NO_IPV6: OnceLock<String> = OnceLock::new();

/// No router advertisements, autoconfigured addresses or DAD: the address comes from the host,
/// and is the VM's alone. Set before eth0 is up, so its link-local address skips DAD too.
fn ipv6_sysctls() -> io::Result<()> {
    for (key, value) in [("accept_ra", "0"), ("autoconf", "0"), ("accept_dad", "0")] {
        std::fs::write(format!("/proc/sys/net/ipv6/conf/{IFACE}/{key}"), value)?;
    }
    Ok(())
}

pub fn setup() -> io::Result<()> {
    let s = Sock(unsafe { std::os::fd::FromRawFd::from_raw_fd(os(libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0))?) });
    let ipv6 = ipv6_sysctls();
    link_up(&s, "lo")?;
    link_up(&s, IFACE)?;
    add_route(&s, GATEWAY, Ipv4Addr::BROADCAST, None)?;
    add_route(&s, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, Some(GATEWAY))?;
    let mut arp: libc::arpreq = unsafe { std::mem::zeroed() };
    (arp.arp_pa, arp.arp_ha.sa_family, arp.arp_flags) = (sockaddr(GATEWAY), libc::ARPHRD_ETHER, libc::ATF_PERM | libc::ATF_COM);
    for (d, s) in arp.arp_ha.sa_data.iter_mut().zip(GATEWAY_MAC) {
        *d = s as libc::c_char;
    }
    name(&mut arp.arp_dev, IFACE);
    s.ioctl(libc::SIOCSARP, &mut arp)?;
    let mut req = ifreq(IFACE);
    s.ioctl(libc::SIOCGIFINDEX, &mut req)?;
    let fd = os(unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) })?;
    let ifindex = unsafe { req.ifr_ifru.ifru_ifindex } as u32;
    let _ = NETLINK.set((fd, ifindex));
    // IPv4 works without it.
    if let Err(e) = ipv6.and_then(|()| request(fd, libc::RTM_NEWNEIGH, libc::NLM_F_CREATE | libc::NLM_F_REPLACE, &gateway_neighbour(ifindex))) {
        crate::log(&format!("no IPv6: {e}"));
        let _ = NO_IPV6.set(e.to_string());
    }
    Ok(())
}

/// The managed addresses, kept in snapshot state under the socket's ACK lock.
struct Addresses {
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    /// The IPv6 default route, there only while there is an IPv6 address: without one, a guest's
    /// IPv6 connection fails at once (no route) rather than waiting on a gateway it cannot use.
    route6: bool,
}

/// Gives eth0 its per-VM /32, and /128 if `ip6` (none deletes a previous one), and optionally
/// nameservers, in order. Runs right after every restore, so it is one RTM_NEWADDR per address on
/// a socket opened at template boot (then RTM_DELADDR of a fork's old one): SIOCSIFADDR, or deleting
/// eth0's last address first, would flush the gateway route and ARP entry.
pub fn configure(ip: Ipv4Addr, ip6: Option<Ipv6Addr>, dns: &[&str]) -> io::Result<()> {
    static ADDRESSES: Mutex<Addresses> = Mutex::new(Addresses { v4: None, v6: None, route6: false });
    let mut a = ADDRESSES.lock().unwrap();
    let (fd, ifindex) = *NETLINK.get().ok_or_else(|| io::Error::other("no netlink socket"))?;
    if let (Some(_), Some(why)) = (ip6, NO_IPV6.get()) {
        return Err(io::Error::other(format!("the guest has no IPv6: {why}")));
    }
    let route = |kind| request(fd, kind, route_flags(kind), &default_route6(ifindex));
    update_addresses(&mut a, ip, ip6, |kind, ip| address_request(fd, ifindex, kind, ip), route)?;
    if !dns.is_empty() {
        resolv_conf(std::path::Path::new("/etc"), dns)?;
    }
    Ok(())
}

/// Replaces DIR/resolv.conf with a rename, so a lookup never reads it empty, through DIR's fd. It
/// follows no symlink (an image's link is replaced, not its target) and opens no special file. A
/// bind-mounted file cannot be renamed over, so it is rewritten in place.
fn resolv_conf(dir: &std::path::Path, dns: &[&str]) -> io::Result<()> {
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    let content: String = dns.iter().map(|d| format!("nameserver {d}\n")).collect();
    let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(dir)?;
    let (fd, name, tmp) = (dir.as_raw_fd(), c"resolv.conf", c"resolv.conf.tmp");
    let at = |name: &std::ffi::CStr, flags| {
        os(unsafe { libc::openat(fd, name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o644) }).map(|f| unsafe { File::from_raw_fd(f) })
    };
    // Reopened through /proc only once its O_PATH fd is known to be a regular file.
    let existing = |options: &mut OpenOptions| {
        let path = at(name, libc::O_PATH)?;
        if !path.metadata()?.is_file() {
            return Err(io::Error::other("resolv.conf is not a regular file"));
        }
        options.open(format!("/proc/self/fd/{}", path.as_raw_fd()))
    };
    if existing(OpenOptions::new().read(true)).and_then(io::read_to_string).is_ok_and(|old| old == content) {
        return Ok(());
    }
    unsafe { libc::unlinkat(fd, tmp.as_ptr(), 0) };
    at(tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?.write_all(content.as_bytes())?;
    let renamed = os(unsafe { libc::renameat(fd, tmp.as_ptr(), fd, name.as_ptr()) });
    unsafe { libc::unlinkat(fd, tmp.as_ptr(), 0) };
    match renamed {
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => existing(OpenOptions::new().write(true).truncate(true))?.write_all(content.as_bytes()),
        r => r.map(drop),
    }
}

/// The IPv4 address, then the IPv6 one and its default route (added with the address, deleted
/// before it).
fn update_addresses(
    a: &mut Addresses,
    ip: Ipv4Addr,
    ip6: Option<Ipv6Addr>,
    mut address: impl FnMut(u16, IpAddr) -> io::Result<()>,
    mut route: impl FnMut(u16) -> io::Result<()>,
) -> io::Result<()> {
    update_address(&mut a.v4, Some(ip), |kind, ip| address(kind, IpAddr::V4(ip)))?;
    if ip6.is_none() && a.route6 {
        match route(libc::RTM_DELROUTE) {
            Err(e) if e.raw_os_error() != Some(libc::ESRCH) => return Err(e),
            _ => a.route6 = false,
        }
    }
    update_address(&mut a.v6, ip6, |kind, ip| address(kind, IpAddr::V6(ip)))?;
    if ip6.is_some() && !a.route6 {
        route(libc::RTM_NEWROUTE)?;
        a.route6 = true;
    }
    Ok(())
}

/// Adds `ip` (none: no address), then deletes the previous one.
fn update_address<A: Copy + PartialEq>(address: &mut Option<A>, ip: Option<A>, mut request: impl FnMut(u16, A) -> io::Result<()>) -> io::Result<()> {
    if let Some(ip) = ip {
        request(libc::RTM_NEWADDR, ip)?;
    }
    // Keep the old address until it is gone, so a failed delete is retried.
    match address.filter(|old| Some(*old) != ip).map(|old| request(libc::RTM_DELADDR, old)) {
        Some(Err(e)) if e.raw_os_error() != Some(libc::EADDRNOTAVAIL) => Err(e),
        _ => {
            *address = ip;
            Ok(())
        }
    }
}

fn attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
    buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

/// struct ifaddrmsg (family, prefixlen, flags, scope, index) and the address: a /32 with IFA_LOCAL
/// too, or a /128 with no DAD (the host gives each VM its own).
fn address_message(ifindex: u32, ip: IpAddr) -> Vec<u8> {
    let mut msg = match ip {
        IpAddr::V4(_) => vec![libc::AF_INET as u8, 32, 0, libc::RT_SCOPE_UNIVERSE],
        IpAddr::V6(_) => vec![libc::AF_INET6 as u8, 128, libc::IFA_F_NODAD as u8, libc::RT_SCOPE_UNIVERSE],
    };
    msg.extend_from_slice(&ifindex.to_ne_bytes());
    match ip {
        IpAddr::V4(ip) => [libc::IFA_LOCAL, libc::IFA_ADDRESS].into_iter().for_each(|kind| attr(&mut msg, kind, &ip.octets())),
        IpAddr::V6(ip) => attr(&mut msg, libc::IFA_ADDRESS, &ip.octets()),
    }
    msg
}

fn address_request(fd: libc::c_int, ifindex: u32, kind: u16, ip: IpAddr) -> io::Result<()> {
    let flags = if kind == libc::RTM_NEWADDR { libc::NLM_F_CREATE | libc::NLM_F_REPLACE } else { 0 };
    request(fd, kind, flags, &address_message(ifindex, ip))
}

/// struct ndmsg (family, pad, index, state, flags, type): GATEWAY6 at GATEWAY_MAC, permanently, as
/// the ARP entry is (no ioctl sets an IPv6 one).
fn gateway_neighbour(ifindex: u32) -> Vec<u8> {
    let mut msg = [&[libc::AF_INET6 as u8, 0, 0, 0][..], &ifindex.to_ne_bytes(), &libc::NUD_PERMANENT.to_ne_bytes(), &[0, 0]].concat();
    attr(&mut msg, libc::NDA_DST, &GATEWAY6.octets());
    attr(&mut msg, libc::NDA_LLADDR, &GATEWAY_MAC);
    msg
}

/// struct rtmsg (family, dst_len, src_len, tos, table, protocol, scope, type, flags): ::/0 via GATEWAY6 on eth0.
fn default_route6(ifindex: u32) -> Vec<u8> {
    let mut msg = vec![libc::AF_INET6 as u8, 0, 0, 0, libc::RT_TABLE_MAIN, libc::RTPROT_BOOT, libc::RT_SCOPE_UNIVERSE, libc::RTN_UNICAST, 0, 0, 0, 0];
    attr(&mut msg, libc::RTA_GATEWAY, &GATEWAY6.octets());
    attr(&mut msg, libc::RTA_OIF, &ifindex.to_ne_bytes());
    msg
}

fn route_flags(kind: u16) -> libc::c_int {
    if kind == libc::RTM_NEWROUTE {
        libc::NLM_F_CREATE | libc::NLM_F_REPLACE
    } else {
        0
    }
}

/// Sends one rtnetlink request, `body` after its header, and waits for its ACK.
fn request(fd: libc::c_int, kind: u16, flags: libc::c_int, body: &[u8]) -> io::Result<()> {
    static SEQUENCE: AtomicU32 = AtomicU32::new(1);
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let len = 16 + body.len();
    let mut msg = Vec::with_capacity(len);
    msg.extend_from_slice(&(len as u32).to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&((flags | libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16).to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&[0; 4]);
    msg.extend_from_slice(body);
    os(unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) })?;
    // An error ACK carries the request back (and may carry extended attributes).
    let mut ack = [0u8; 1024];
    loop {
        match os(unsafe { libc::recv(fd, ack.as_mut_ptr().cast(), ack.len(), 0) }) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
            Ok(n) => {
                if let Some(result) = matching_ack(&ack[..n as usize], seq) {
                    return result;
                }
            }
        }
    }
}

fn matching_ack(mut data: &[u8], seq: u32) -> Option<io::Result<()>> {
    while data.len() >= 16 {
        let len = u32::from_ne_bytes(data[..4].try_into().unwrap()) as usize;
        if len < 16 || len > data.len() {
            return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "malformed netlink ACK")));
        }
        if u32::from_ne_bytes(data[8..12].try_into().unwrap()) == seq && u16::from_ne_bytes(data[4..6].try_into().unwrap()) == libc::NLMSG_ERROR as u16 {
            if len < 20 {
                return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "short netlink ACK")));
            }
            let code = i32::from_ne_bytes(data[16..20].try_into().unwrap());
            return Some(if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code.saturating_neg())) });
        }
        let aligned = (len + 3) & !3;
        data = data.get(aligned..).unwrap_or_default();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_is_replaced_atomically_and_unchanged_content_is_skipped() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::test_util::TempDir::new("resolv");
        let (path, tmp) = (dir.join("resolv.conf"), dir.join("resolv.conf.tmp"));
        resolv_conf(&dir, &["1.1.1.1"]).unwrap();
        let old = std::fs::File::open(&path).unwrap();
        let ino = old.metadata().unwrap().ino();
        resolv_conf(&dir, &["1.1.1.1"]).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino);
        resolv_conf(&dir, &["8.8.8.8"]).unwrap();
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), ino);
        assert_eq!(std::io::read_to_string(old).unwrap(), "nameserver 1.1.1.1\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "nameserver 8.8.8.8\n");
        assert!(!tmp.exists());
        resolv_conf(&dir, &["192.0.2.53", "2001:db8::53"]).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "nameserver 192.0.2.53\nnameserver 2001:db8::53\n");
        resolv_conf(&dir, &["8.8.8.8"]).unwrap();
        // A failed replacement leaves the published file intact.
        std::fs::create_dir(&tmp).unwrap();
        resolv_conf(&dir, &["8.8.8.8"]).unwrap();
        assert!(resolv_conf(&dir, &["9.9.9.9"]).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "nameserver 8.8.8.8\n");
        std::fs::remove_dir(&tmp).unwrap();
        // So does one that cannot rename over a directory.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(resolv_conf(&dir, &["1.1.1.1"]).is_err());
        assert!(!tmp.exists());
    }

    #[test]
    fn resolv_conf_follows_no_symlink_and_opens_no_fifo() {
        let dir = crate::test_util::TempDir::new("resolv-links");
        let (path, tmp, victim) = (dir.join("resolv.conf"), dir.join("resolv.conf.tmp"), dir.join("victim"));
        let fifo = |p: &std::path::Path| assert!(std::process::Command::new("mkfifo").arg(p).status().unwrap().success());
        std::fs::write(&victim, "keep").unwrap();
        let plants: [Box<dyn Fn()>; 5] = [
            Box::new(|| std::os::unix::fs::symlink(&victim, &path).unwrap()),
            Box::new(|| std::os::unix::fs::symlink(dir.join("missing"), &path).unwrap()),
            Box::new(|| std::os::unix::fs::symlink(&victim, &tmp).unwrap()),
            Box::new(|| fifo(&path)),
            Box::new(|| fifo(&tmp)),
        ];
        for plant in plants {
            plant();
            resolv_conf(&dir, &["1.1.1.1"]).unwrap();
            assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "nameserver 1.1.1.1\n");
            assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
            assert!(!tmp.exists());
            std::fs::remove_file(&path).unwrap();
        }
        // The directory itself is not followed either.
        let link = dir.join("link");
        std::os::unix::fs::symlink(&*dir, &link).unwrap();
        assert!(resolv_conf(&link, &["1.1.1.1"]).is_err());
        assert!(!path.exists());
    }

    #[test]
    #[ignore] // root: a bind mount needs CAP_SYS_ADMIN (CI's root step runs it)
    fn resolv_conf_rewrites_a_bind_mounted_file_in_place() {
        crate::test_util::assert_root();
        use std::os::unix::ffi::OsStrExt;
        let dir = crate::test_util::TempDir::new("resolv-bind");
        let (path, source) = (dir.join("resolv.conf"), dir.join("source"));
        std::fs::write(&path, "").unwrap();
        std::fs::write(&source, "nameserver 8.8.8.8\n").unwrap();
        let c = |p: &std::path::Path| std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        let mounted = unsafe { libc::mount(c(&source).as_ptr(), c(&path).as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) };
        assert_eq!(mounted, 0, "bind mount: {}", std::io::Error::last_os_error());
        let result = resolv_conf(&dir, &["1.1.1.1"]);
        unsafe { libc::umount2(c(&path).as_ptr(), libc::MNT_DETACH) };
        result.unwrap();
        assert_eq!(std::fs::read_to_string(&source).unwrap(), "nameserver 1.1.1.1\n");
        assert!(!dir.join("resolv.conf.tmp").exists());
    }

    #[test]
    fn a_new_address_is_added_before_the_previous_one_is_deleted() {
        let old = Ipv4Addr::new(10, 0, 0, 1);
        let new = Ipv4Addr::new(10, 0, 0, 2);
        let mut address = None;
        for (ip, expected) in
            [(old, vec![(libc::RTM_NEWADDR, old)]), (old, vec![(libc::RTM_NEWADDR, old)]), (new, vec![(libc::RTM_NEWADDR, new), (libc::RTM_DELADDR, old)])]
        {
            let mut sent = Vec::new();
            update_address(&mut address, Some(ip), |kind, ip| {
                sent.push((kind, ip));
                Ok(())
            })
            .unwrap();
            assert_eq!(sent, expected);
            assert_eq!(address, Some(ip));
        }
        // A failed add keeps the old address; one already gone is not an error.
        assert!(update_address(&mut address, Some(old), |_, _| Err(io::Error::other("add failed"))).is_err());
        assert_eq!(address, Some(new));
        // A failed delete must remain retryable on the next configure.
        assert!(update_address(&mut address, Some(old), |kind, _| {
            if kind == libc::RTM_DELADDR {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            } else {
                Ok(())
            }
        })
        .is_err());
        assert_eq!(address, Some(new));
        let mut retry = Vec::new();
        update_address(&mut address, Some(old), |kind, ip| {
            retry.push((kind, ip));
            Ok(())
        })
        .unwrap();
        assert_eq!(retry, vec![(libc::RTM_NEWADDR, old), (libc::RTM_DELADDR, new)]);
        address = Some(new);
        let gone = |kind, _| if kind == libc::RTM_DELADDR { Err(io::Error::from_raw_os_error(libc::EADDRNOTAVAIL)) } else { Ok(()) };
        update_address(&mut address, Some(old), gone).unwrap();
        assert_eq!(address, Some(old));
    }

    #[derive(Debug, PartialEq)]
    enum Sent {
        Address(u16, IpAddr),
        Route(u16),
    }

    fn update(a: &mut Addresses, ip: Ipv4Addr, ip6: Option<Ipv6Addr>, fail: Option<u16>) -> (io::Result<()>, Vec<Sent>) {
        let sent = std::cell::RefCell::new(Vec::new());
        let result = |kind| if Some(kind) == fail { Err(io::Error::from_raw_os_error(libc::EPERM)) } else { Ok(()) };
        let r = update_addresses(
            a,
            ip,
            ip6,
            |kind, ip| {
                sent.borrow_mut().push(Sent::Address(kind, ip));
                result(kind)
            },
            |kind| {
                sent.borrow_mut().push(Sent::Route(kind));
                result(kind)
            },
        );
        (r, sent.into_inner())
    }

    #[test]
    fn the_ipv6_address_and_route_come_and_go_with_start6() {
        use Sent::*;
        let (v4, v6) = (Ipv4Addr::new(10, 0, 0, 2), "fd00::a00:2".parse::<Ipv6Addr>().unwrap());
        let (new, del) = (libc::RTM_NEWADDR, libc::RTM_DELADDR);
        let mut a = Addresses { v4: None, v6: None, route6: false };
        // START (a template's, or an older host's): IPv4 alone, no IPv6 route.
        let (r, sent) = update(&mut a, v4, None, None);
        assert!(r.is_ok() && sent == [Address(new, IpAddr::V4(v4))], "{sent:?}");
        // START6: the /128, then its route, once.
        let (r, sent) = update(&mut a, v4, Some(v6), None);
        assert!(r.is_ok() && sent == [Address(new, IpAddr::V4(v4)), Address(new, IpAddr::V6(v6)), Route(libc::RTM_NEWROUTE)], "{sent:?}");
        let (r, sent) = update(&mut a, v4, Some(v6), None);
        assert!(r.is_ok() && sent == [Address(new, IpAddr::V4(v4)), Address(new, IpAddr::V6(v6))], "{sent:?}");
        // START again: the route goes first, then the address.
        let (r, sent) = update(&mut a, v4, None, None);
        assert!(r.is_ok() && sent == [Address(new, IpAddr::V4(v4)), Route(libc::RTM_DELROUTE), Address(del, IpAddr::V6(v6))], "{sent:?}");
        assert!(a.v6.is_none() && !a.route6);
        // A failed route is retried on the next START6, the address kept.
        let (r, _) = update(&mut a, v4, Some(v6), Some(libc::RTM_NEWROUTE));
        assert!(r.is_err() && a.v6 == Some(v6) && !a.route6);
        let (r, sent) = update(&mut a, v4, Some(v6), None);
        assert!(r.is_ok() && sent.last() == Some(&Route(libc::RTM_NEWROUTE)) && a.route6, "{sent:?}");
        // A failed IPv4 address leaves IPv6 untouched.
        let (r, sent) = update(&mut a, v4, None, Some(new));
        assert!(r.is_err() && sent == [Address(new, IpAddr::V4(v4))] && a.route6, "{sent:?}");
    }

    #[test]
    fn netlink_messages_are_laid_out_as_the_kernel_reads_them() {
        let v4 = address_message(7, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(v4.len(), 8 + 2 * 8);
        assert_eq!(&v4[..8], &[libc::AF_INET as u8, 32, 0, 0, 7, 0, 0, 0]);
        let v6 = address_message(7, IpAddr::V6("fd00::a00:2".parse().unwrap()));
        assert_eq!(&v6[..8], &[libc::AF_INET6 as u8, 128, libc::IFA_F_NODAD as u8, 0, 7, 0, 0, 0]);
        assert_eq!(&v6[8..12], &[20, 0, libc::IFA_ADDRESS as u8, 0]);
        assert_eq!(v6[12..], "fd00::a00:2".parse::<Ipv6Addr>().unwrap().octets());
        let n = gateway_neighbour(7);
        assert_eq!(&n[..12], &[libc::AF_INET6 as u8, 0, 0, 0, 7, 0, 0, 0, libc::NUD_PERMANENT as u8, 0, 0, 0]);
        assert_eq!((&n[12..16], &n[16..32]), (&[20, 0, libc::NDA_DST as u8, 0][..], &GATEWAY6.octets()[..]));
        // A 6-byte MAC, padded to 4.
        assert_eq!((&n[32..36], &n[36..42], n.len()), (&[10, 0, libc::NDA_LLADDR as u8, 0][..], &GATEWAY_MAC[..], 44));
        let r = default_route6(7);
        assert_eq!(&r[..12], &[libc::AF_INET6 as u8, 0, 0, 0, libc::RT_TABLE_MAIN, libc::RTPROT_BOOT, 0, libc::RTN_UNICAST, 0, 0, 0, 0]);
        assert_eq!((&r[12..16], &r[16..32]), (&[20, 0, libc::RTA_GATEWAY as u8, 0][..], &GATEWAY6.octets()[..]));
        assert_eq!(&r[32..], &[8, 0, libc::RTA_OIF as u8, 0, 7, 0, 0, 0]);
    }

    #[test]
    #[ignore] // root: a network namespace and a veth (CI's root step runs it)
    fn setup_and_configure_give_eth0_its_addresses_and_gateways() {
        crate::test_util::assert_root();
        // In a network namespace of its own (a thread's), with an eth0 to set up as the guest's.
        std::thread::spawn(|| {
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0, "{}", io::Error::last_os_error());
            let ip = |args: &str| {
                let out = std::process::Command::new("ip").args(args.split(' ')).output().unwrap();
                assert!(out.status.success(), "ip {args}: {}", String::from_utf8_lossy(&out.stderr));
                String::from_utf8(out.stdout).unwrap()
            };
            ip("link add eth0 type veth peer name host0");
            ip("link set host0 up");
            setup().unwrap();
            for key in ["accept_ra", "autoconf", "accept_dad"] {
                assert_eq!(std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/eth0/{key}")).unwrap(), "0\n", "{key}");
            }
            let neigh = ip("-6 neigh show dev eth0");
            assert!(neigh.contains("fe80::1 lladdr 06:00:a9:fe:01:01 PERMANENT"), "{neigh}");
            assert!(ip("-4 neigh show dev eth0").contains("169.254.1.1 lladdr 06:00:a9:fe:01:01 PERMANENT"));
            // No IPv6 default route until there is an address to use it with.
            assert_eq!(ip("-6 route show default"), "");
            let (v4, v6) = (Ipv4Addr::new(10, 0, 0, 2), "fd00::a00:2".parse().unwrap());
            configure(v4, Some(v6), &[]).unwrap();
            let addrs = ip("-6 addr show dev eth0");
            assert!(addrs.contains("inet6 fd00::a00:2/128 scope global nodad"), "{addrs}");
            assert!(ip("-4 addr show dev eth0").contains("inet 10.0.0.2/32"));
            let route = ip("-6 route show default");
            assert!(route.starts_with("default via fe80::1 dev eth0"), "{route}");
            // Again (a restore's START6), then another fork's address.
            configure(v4, Some(v6), &[]).unwrap();
            configure(Ipv4Addr::new(10, 0, 0, 3), Some("fd00::a00:3".parse().unwrap()), &[]).unwrap();
            let addrs = ip("-6 addr show dev eth0 scope global");
            assert!(addrs.contains("fd00::a00:3/128") && !addrs.contains("fd00::a00:2"), "{addrs}");
            // START: IPv4 alone; the IPv6 address and route go, the gateway's neighbour stays.
            configure(v4, None, &[]).unwrap();
            assert_eq!((ip("-6 addr show dev eth0 scope global"), ip("-6 route show default")), (String::new(), String::new()));
            assert!(ip("-6 neigh show dev eth0").contains("fe80::1 lladdr 06:00:a9:fe:01:01 PERMANENT"));
            assert!(ip("-4 route show default").contains("default via 169.254.1.1 dev eth0"));
        })
        .join()
        .unwrap();
    }

    #[test]
    fn the_gateway_is_the_hosts() {
        // flexvm/src/net.rs gives each tap GATEWAY_MAC and fe80::1.
        assert_eq!((GATEWAY6.to_string().as_str(), GATEWAY_MAC), ("fe80::1", [0x06, 0x00, 0xa9, 0xfe, 0x01, 0x01]));
    }

    fn ack(seq: u32, code: i32) -> Vec<u8> {
        let mut data = vec![0; 20];
        data[..4].copy_from_slice(&20u32.to_ne_bytes());
        data[4..6].copy_from_slice(&(libc::NLMSG_ERROR as u16).to_ne_bytes());
        data[8..12].copy_from_slice(&seq.to_ne_bytes());
        data[16..20].copy_from_slice(&code.to_ne_bytes());
        data
    }

    #[test]
    fn ack_matches_sequence_and_reports_errors() {
        assert!(matching_ack(&ack(1, -libc::EPERM), 2).is_none());
        let data = [ack(1, -libc::EPERM), ack(2, 0)].concat();
        matching_ack(&data, 2).unwrap().unwrap();
        assert_eq!(matching_ack(&ack(2, -libc::EPERM), 2).unwrap().unwrap_err().raw_os_error(), Some(libc::EPERM));
        let mut short = ack(2, 0);
        short[..4].copy_from_slice(&16u32.to_ne_bytes());
        assert!(matching_ack(&short[..16], 2).unwrap().is_err());
    }
}
