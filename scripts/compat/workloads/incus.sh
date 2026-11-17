#!/bin/sh
# Stock Incus container/image/storage lifecycle, with normal unprivileged instances.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-incus-$nonce
diagnostics() {
    status=$?
    trap - 0
    if [ "$status" -ne 0 ]; then
        systemctl --no-pager -l status incus.service incus-startup.service || true
        journalctl --no-pager -u incus.service -u incus-startup.service -n 80 || true
        for instance in fc fc-clone; do
            timeout 10 incus info --show-log "$instance" || true
            timeout 10 incus exec "$instance" -- /bin/sh -c 'systemctl list-jobs; journalctl --no-pager -b -n 80; cat /etc/resolv.conf; ip route' || true
        done
    fi
    exit "$status"
}
trap diagnostics 0
leader() {
    incus query /1.0/instances/fc/state | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("metadata",d)["pid"])'
}
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends incus incus-client dnsmasq-base iptables lxcfs curl python3 ca-certificates
    mkdir "$base"
    systemctl start lxcfs.service incus.service incus-startup.service
    incus admin init --minimal
    incus query /1.0/storage-pools/default | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("metadata",d)["driver"] == "dir"'
    incus network set incusbr0 ipv4.address 10.89.0.1/24
    incus network set incusbr0 ipv4.nat true
    incus network set incusbr0 ipv6.address none
    test "$(incus profile device get default eth0 network)" = incusbr0
    incus launch images:debian/13 fc -c limits.memory=512MiB -c limits.cpu.allowance=50ms/100ms -c limits.processes=128
    test "$(incus config get fc security.privileged)" != true
    incus config get fc volatile.base_image > "$base/fingerprint"
    incus image info "$(cat "$base/fingerprint")"
    incus exec fc -- /bin/sh -ec '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends python3 ca-certificates
        mkdir -p /var/www
        printf %s "$1" > /var/www/index.html
        printf %s "$1" > /var/lib/flexvm-marker' sh "$nonce"
    incus storage volume create default state
    incus config device add fc data disk pool=default source=state path=/data
    incus exec fc -- /bin/sh -ec 'printf %s "$1" > /data/marker' sh "$nonce"
    cat > "$base/state-probe.py" <<'PYPROBE'
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
PYPROBE
    cat > "$base/state-probe.service" <<'EOF'
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/state-probe.py
WorkingDirectory=/var/www
MemoryMax=67108864
TasksMax=16
CPUQuota=50%
[Install]
WantedBy=multi-user.target
EOF
    incus file push "$base/state-probe.py" fc/usr/local/bin/state-probe.py
    incus file push "$base/state-probe.service" fc/etc/systemd/system/state-probe.service
    incus exec fc -- systemctl enable state-probe.service
    incus stop fc --timeout 30
    incus snapshot create fc clean
    incus copy fc/clean fc-clone
    incus start fc-clone
    test "$(incus exec fc-clone -- cat /var/lib/flexvm-marker)" = "$nonce"
    test "$(incus exec fc-clone -- cat /data/marker)" = "$nonce"
    incus stop fc-clone --timeout 30
    incus delete fc-clone
    incus snapshot restore fc clean
    incus start fc
    for attempt in $(seq 1 100); do
        if incus exec fc -- test -s /run/state-probe.json; then break; fi
        sleep .1
    done
    leader > "$base/leader"
    incus exec fc -- cat /run/state-probe.json > "$base/initial"
    systemctl show --property=MainPID --value incus.service > "$base/daemon"
    cat "/proc/$(cat "$base/daemon")/stat" > "$base/daemon-stat"
    incus version
    dpkg-query -W incus incus-client
    ;;
verify)
    systemctl is-active --quiet incus.service incus-startup.service lxcfs.service
    test "$(systemctl show --property=MainPID --value incus.service)" = "$(cat "$base/daemon")"
    python3 - "$base/daemon-stat" "/proc/$(cat "$base/daemon")/stat" <<'PYDAEMON'
import pathlib, sys
before, now = (pathlib.Path(p).read_text().rsplit(')', 1)[1].split()[19] for p in sys.argv[1:])
assert before == now, (before, now)
PYDAEMON
    pid=$(leader)
    test "$pid" = "$(cat "$base/leader")"
    test "$(cat /proc/$pid/comm)" = systemd
    test "$(awk '{print $2}' /proc/$pid/uid_map)" != 0
    test "$(incus config get fc volatile.base_image)" = "$(cat "$base/fingerprint")"
    test "$(incus exec fc -- cat /var/lib/flexvm-marker)" = "$nonce"
    test "$(incus exec fc -- cat /data/marker)" = "$nonce"
    incus exec fc -- /bin/sh -exc '
        cat /proc/self/cgroup /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/cpu.max
        systemctl is-active --quiet state-probe.service
        group=$(systemctl show --property=ControlGroup --value state-probe.service)
        test "$(cat /sys/fs/cgroup$group/memory.max)" = 67108864
        test "$(cat /sys/fs/cgroup$group/pids.max)" = 16
        test "$(cat /sys/fs/cgroup$group/cpu.max)" = "50000 100000"
        test "$(cat /sys/fs/cgroup/memory.max)" = 536870912
        test "$(cat /sys/fs/cgroup/pids.max)" = 128
        test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
        python3 -c "import urllib.request; urllib.request.urlopen(\"http://example.com\", timeout=15).read()"'
    ip=$(incus exec fc -- hostname -I | awk '{print $1}')
    test "$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 "http://$ip:18088")" = "$nonce"
    python3 - "$base/initial" "/proc/$pid/root/run/state-probe.json" <<'PYCHECK'
import json, pathlib, sys, time
before = json.loads(pathlib.Path(sys.argv[1]).read_text())
path = pathlib.Path(sys.argv[2])
now = json.loads(path.read_text())
assert all(now[key] == before[key] for key in ('pid', 'start', 'cookie', 'machine')), (before, now)
time.sleep(.2)
assert json.loads(path.read_text())['counter'] > now['counter']
print(now)
PYCHECK
    printf 'INCUS_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
