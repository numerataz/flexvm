#!/bin/sh
# A stock, user-namespaced systemd-nspawn OS, controlled by machined.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-nspawn-$nonce
root=/var/lib/machines/fvns
wait_boot() {
    for attempt in $(seq 1 100); do
        leader=$(machinectl show fvns --property=Leader --value)
        if [ -s "/proc/$leader/root/run/state-probe.json" ]; then return; fi
        sleep .1
    done
    return 1
}
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends systemd-container debootstrap ubuntu-keyring dbus iptables curl
    case $(dpkg --print-architecture) in
        amd64) mirror=http://archive.ubuntu.com/ubuntu ;;
        arm64) mirror=http://ports.ubuntu.com/ubuntu-ports ;;
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
    mkdir -p "$root/etc/systemd/network" /etc/systemd/nspawn /etc/systemd/network
    cat > "$root/etc/systemd/network/10-host.network" <<'EOF'
[Match]
Name=host0
[Network]
Address=172.31.88.2/24
Gateway=172.31.88.1
EOF
    printf 'nameserver %s\n' "$(awk '/^nameserver / {print $2; exit}' /etc/resolv.conf)" > "$root/etc/resolv.conf"
    cat > /etc/systemd/network/10-fvns.network <<'EOF'
[Match]
Name=ve-fvns
[Network]
Address=172.31.88.1/24
IPForward=ipv4
EOF
    cat > /etc/systemd/nspawn/fvns.nspawn <<'EOF'
[Exec]
Boot=yes
PrivateUsers=no
[Files]
PrivateUsersOwnership=chown
[Network]
VirtualEthernet=yes
EOF
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
    systemctl start dbus.service systemd-machined.service systemd-networkd.service
    sysctl -w net.ipv4.ip_forward=1
    iptables -t nat -A POSTROUTING -s 172.31.88.0/24 -o eth0 -j MASQUERADE
    systemctl start systemd-nspawn@fvns.service
    wait_boot
    test "$(awk '{print $2}' "/proc/$leader/uid_map")" = 0
    test "$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://172.31.88.2:18088)" = "$nonce"
    machinectl poweroff fvns
    for attempt in $(seq 1 300); do
        if [ "$(systemctl show --property=ActiveState --value systemd-nspawn@fvns.service)" = inactive ]; then break; fi
        sleep .1
    done
    test "$(systemctl show --property=ActiveState --value systemd-nspawn@fvns.service)" = inactive
    test "$(systemctl show --property=ExecMainStatus --value systemd-nspawn@fvns.service)" = 0
    test ! -e "/proc/$leader"
    if machinectl show fvns; then exit 1; fi
    printf 'NSPAWN_PRIVILEGED_SHUTDOWN_OK\n'
    sed -i 's/PrivateUsers=no/PrivateUsers=pick/' /etc/systemd/nspawn/fvns.nspawn
    systemctl start systemd-nspawn@fvns.service
    wait_boot
    printf '%s\n' "$leader" > "$base/leader"
    cp "/proc/$leader/root/run/state-probe.json" "$base/initial"
    dpkg-query -W systemd-container debootstrap
    ;;
verify)
    leader=$(machinectl show fvns --property=Leader --value)
    test "$leader" = "$(cat "$base/leader")"
    test "$(cat "/proc/$leader/comm")" = systemd
    test "$(awk '{print $2}' "/proc/$leader/uid_map")" != 0
    systemctl is-active --quiet systemd-nspawn@fvns.service
    systemd-run --machine=fvns --quiet --wait --pipe /bin/sh -ec '
        systemctl is-active --quiet state-probe.service
        group=$(systemctl show --property=ControlGroup --value state-probe.service)
        test "$(cat /sys/fs/cgroup$group/memory.max)" = 67108864
        test "$(cat /sys/fs/cgroup$group/pids.max)" = 16
        test "$(cat /sys/fs/cgroup$group/cpu.max)" = "50000 100000"
        python3 -c "import urllib.request; urllib.request.urlopen(\"http://example.com\", timeout=15).read()"'
    test "$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://172.31.88.2:18088)" = "$nonce"
    python3 - "$base/initial" "/proc/$leader/root/run/state-probe.json" <<'PY'
import json, pathlib, sys, time
before = json.loads(pathlib.Path(sys.argv[1]).read_text())
path = pathlib.Path(sys.argv[2])
now = json.loads(path.read_text())
assert all(now[key] == before[key] for key in ('pid', 'start', 'cookie', 'machine')), (before, now)
time.sleep(.2)
assert json.loads(path.read_text())['counter'] > now['counter']
print(now)
PY
    printf 'NSPAWN_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
