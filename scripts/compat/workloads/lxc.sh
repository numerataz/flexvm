#!/bin/sh
# Stock LXC launched by a normal user through a delegated systemd user service.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-lxc-$nonce
user=fl$(printf %.12s "$nonce")
as_user() { runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" "$@"; }
# lxc-attach moves itself into the container's cgroup. Start it within the
# user's delegated manager subtree, alongside the LXC service.
attach() { as_user systemd-run --user --quiet --wait --pipe --collect --service-type=exec -- lxc-attach -n fvuser -- "$@"; }
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends lxc lxc-templates debootstrap ubuntu-keyring ca-certificates uidmap \
        dbus dbus-user-session libpam-systemd passwd dnsmasq-base iptables curl python3
    root=/var/lib/lxc/fvpriv/rootfs
    case $(dpkg --print-architecture) in
        amd64) mirror=https://archive.ubuntu.com/ubuntu ;;
        arm64) mirror=https://ports.ubuntu.com/ubuntu-ports ;;
        *) exit 2 ;;
    esac
    mkdir -p "$base" /var/lib/machines
    # debootstrap starts wget for each package; avoid its multi-minute default
    # connection timeout when one of a mirror's addresses does not answer.
    printf 'timeout = 15\ntries = 3\n' > "$base/wgetrc"
    export WGETRC="$base/wgetrc"
    if ! debootstrap --variant=minbase --include=systemd-sysv,dbus,python3,iproute2,ca-certificates noble "$root" "$mirror"; then
        tail -n 1000 "$root/debootstrap/debootstrap.log" >&2 || true
        exit 1
    fi
    rm -f "$root"/var/cache/apt/archives/*.deb

    mkdir -p "$root/etc/systemd/network"
    cat > "$root/etc/systemd/network/10-eth.network" <<'EOF'
[Match]
Name=eth0
[Network]
Address=10.0.3.100/24
Gateway=10.0.3.1
EOF
    printf 'nameserver %s\n' "$(awk '/^nameserver / {print $2; exit}' /etc/resolv.conf)" > "$root/etc/resolv.conf"
    cat > "$root/usr/local/bin/state-probe.py" <<'PY'
import http.server, json, os, pathlib, secrets, threading, time
cookie = secrets.token_hex(16)
threading.Thread(target=lambda: http.server.HTTPServer(('0.0.0.0', 18088), http.server.SimpleHTTPRequestHandler).serve_forever(), daemon=True).start()
counter = 0
while True:
    counter += 1
    value = dict(cookie=cookie, counter=counter, pid=os.getpid(),
                 start=pathlib.Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
                 machine=pathlib.Path('/etc/machine-id').read_text().strip())
    pathlib.Path('/run/state-probe.new').write_text(json.dumps(value))
    os.replace('/run/state-probe.new', '/run/state-probe.json')
    time.sleep(.05)
PY
    mkdir -p "$root/var/www"
    printf '%s' "$nonce" > "$root/var/www/index.html"
    cat > "$root/etc/systemd/system/state-probe.service" <<'EOF'
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/state-probe.py
WorkingDirectory=/var/www
MemoryMax=67108864
TasksMax=16
CPUQuota=50%
[Install]
WantedBy=multi-user.target
EOF

    chroot "$root" systemctl enable systemd-networkd.service state-probe.service
    cat > /var/lib/lxc/fvpriv/config <<EOF
lxc.include = /usr/share/lxc/config/ubuntu.common.conf
lxc.rootfs.path = dir:$root
lxc.uts.name = fvpriv
lxc.net.0.type = veth
lxc.net.0.link = lxcbr0
lxc.net.0.flags = up
lxc.net.0.ipv4.address = 10.0.3.100/24
lxc.net.0.ipv4.gateway = 10.0.3.1
lxc.cgroup2.memory.max = 134217728
lxc.cgroup2.pids.max = 128
lxc.cgroup2.cpu.max = 50000 100000
EOF
    systemctl start dbus.service systemd-logind.service lxc-net.service
    lxc-start -n fvpriv -d
    lxc-wait -n fvpriv -s RUNNING -t 30
    for attempt in $(seq 1 100); do
        if lxc-attach -n fvpriv -- test -s /run/state-probe.json; then break; fi
        sleep .1
    done
    lxc-attach -n fvpriv -- systemctl is-active --quiet state-probe.service
    lxc-stop --nokill -n fvpriv -t 30
    lxc-wait -n fvpriv -s STOPPED -t 30
    useradd -m -s /bin/sh "$user"
    uid=$(id -u "$user")
    printf '%s\n' "$uid" > "$base/uid"
    subuid=$(awk -F: -v user="$user" '$1 == user {print $2; exit}' /etc/subuid)
    subgid=$(awk -F: -v user="$user" '$1 == user {print $2; exit}' /etc/subgid)
    test -n "$subuid"; test -n "$subgid"
    user_home=/home/$user
    install -d -m 755 -o "$user" -g "$user" "$user_home/.local" "$user_home/.local/share" "$user_home/.local/share/lxc" "$user_home/.local/share/lxc/fvuser"
    chmod 755 "$user_home"
    mv "$root" "$user_home/.local/share/lxc/fvuser/rootfs"
    root=$user_home/.local/share/lxc/fvuser/rootfs
    python3 - "$root" "$subuid" "$subgid" <<'PYSHIFT'
import os, stat, sys
seen = set()
root, uid, gid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for path, dirs, files in os.walk(root, followlinks=False):
    for entry in [path] + [os.path.join(path, name) for name in files] + [os.path.join(path, name) for name in dirs if os.path.islink(os.path.join(path, name))]:
        value = os.lstat(entry)
        inode = (value.st_dev, value.st_ino)
        if inode in seen:
            continue
        seen.add(inode)
        assert value.st_uid < 65536 and value.st_gid < 65536, (entry, value)
        os.lchown(entry, uid + value.st_uid, gid + value.st_gid)
        if not stat.S_ISLNK(value.st_mode):
            os.chmod(entry, stat.S_IMODE(value.st_mode))
PYSHIFT
    sed -e "s|dir:/var/lib/lxc/fvpriv/rootfs|dir:$root|" -e 's/fvpriv/fvuser/g' /var/lib/lxc/fvpriv/config > "$user_home/.local/share/lxc/fvuser/config"
    printf 'lxc.idmap = u 0 %s 65536\nlxc.idmap = g 0 %s 65536\n' "$subuid" "$subgid" >> "$user_home/.local/share/lxc/fvuser/config"
    chown "$user:$user" "$user_home/.local/share/lxc/fvuser/config" "$base"
    printf '%s veth lxcbr0 2\n' "$user" >> /etc/lxc/lxc-usernet
    loginctl enable-linger "$user"
    systemctl start "user@$uid.service"
    as_user systemd-run --user --unit=flexvm-lxc --property=Delegate=yes -- lxc-start -n fvuser -F -o "$base/lxc.log" -l DEBUG
    as_user lxc-wait -n fvuser -s RUNNING -t 30
    for attempt in $(seq 1 100); do
        if attach test -s /run/state-probe.json; then break; fi
        sleep .1
    done
    as_user lxc-info -n fvuser -pH > "$base/leader"
    attach cat /run/state-probe.json > "$base/initial"
    dpkg-query -W lxc lxc-templates uidmap
    ;;
verify)
    uid=$(cat "$base/uid")
    leader=$(as_user lxc-info -n fvuser -pH)
    test "$leader" = "$(cat "$base/leader")"
    test "$(cat /proc/$leader/comm)" = systemd
    test "$(awk '{print $2}' /proc/$leader/uid_map)" != 0
    as_user systemctl --user is-active --quiet flexvm-lxc.service
    attach /bin/sh -ec '
        systemctl is-active --quiet state-probe.service
        test "$(cat /sys/fs/cgroup/memory.max)" = 134217728
        test "$(cat /sys/fs/cgroup/pids.max)" = 128
        test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
        python3 -c "import urllib.request; urllib.request.urlopen(\"http://example.com\", timeout=15).read()"'
    test "$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://10.0.3.100:18088)" = "$nonce"
    python3 - "$base/initial" "/proc/$leader/root/run/state-probe.json" <<'PYCHECK'
import json, pathlib, sys, time
before = json.loads(pathlib.Path(sys.argv[1]).read_text())
path = pathlib.Path(sys.argv[2])
now = json.loads(path.read_text())
assert all(now[key] == before[key] for key in ('pid', 'start', 'cookie', 'machine')), (before, now)
time.sleep(.2)
assert json.loads(path.read_text())['counter'] > now['counter']
print(now)
PYCHECK
    printf 'LXC_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
