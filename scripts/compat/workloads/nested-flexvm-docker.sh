#!/bin/sh
# Run the normal native FlexVM CLI inside a software-backed guest and run Docker
# (overlay2, cgroup v2 limits, bridge DNS, published ports, BuildKit, live
# container continuity) inside that nested FlexVM across inner and outer lifecycle.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-nested-docker-$nonce
cli() { /nested-input/flexvm --state "$base/state" --run "$base/run" "$@"; }
dexec() { cli exec docker-vm "$@"; }
docker() { dexec docker "$@"; }

traffic_control() {
    unshare --net /bin/sh -ec '
        tc qdisc add dev lo clsact
        tc filter add dev lo ingress protocol all pref 1 bpf da bytecode "1,6 0 0 0,"
        tc qdisc add dev lo root handle 1: plug
        tc qdisc change dev lo root handle 1: plug release_indefinite
        tc -j qdisc show dev lo'
}

check_live_container() {
    expected_pid=$(cat "$base/srv-pid")
    cookie=$(awk '{print $1}' "$base/probe")
    dexec sh -ec '
        expected_pid=$1 cookie=$2 nonce=$3
        test "$(docker info --format "{{.Driver}} {{.CgroupVersion}}")" = "overlay2 2"
        test "$(docker inspect --format "{{.State.Running}} {{.State.Pid}}" nested-srv)" = "true $expected_pid"
        probe=$(docker exec nested-srv sh -ec '\''
            expected=$1
            set -- $(cat /tmp/probe)
            test "$1" = "$expected"
            before=$2
            i=0
            while [ "$i" -lt 50 ]; do
                i=$((i + 1))
                set -- $(cat /tmp/probe)
                test "$1" = "$expected"
                if [ "$2" -gt "$before" ]; then printf "%s %s\n" "$1" "$2"; exit 0; fi
                sleep .2
            done
            echo "nested docker container counter did not advance" >&2
            exit 1'\'' sh "$cookie")
        test "$(wget -qO- http://127.0.0.1:18080/marker)" = "$nonce"
        docker run --rm --network nested-net -v nested-data:/data -e "NONCE=$nonce" \
            flexvm-nested-base:local sh -ec '\''
                test "$(wget -qO- http://nested-srv:8080/marker)" = "$NONCE"
                test "$(cat /data/marker)" = "$NONCE"'\''
        printf "%s\n" "$probe"
    ' sh "$expected_pid" "$cookie" "$nonce" > "$base/probe-now"
}

case $step in
prepare)
    if ! (command -v mkfs.ext4 >/dev/null && command -v debugfs >/dev/null &&
          command -v python3 >/dev/null && command -v tc >/dev/null &&
          command -v unshare >/dev/null); then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends e2fsprogs python3 iproute2 util-linux
    fi
    traffic_control
    test -c /dev/kvm
    test -c /dev/net/tun
    # Enable forwarding (and NAT when iptables is present) plus DNS for the inner TAP.
    sysctl -w net.ipv4.ip_forward=1
    if command -v iptables >/dev/null; then
        iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null ||
            iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        iptables -C FORWARD -i eth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null ||
            iptables -A FORWARD -i eth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        iptables -C FORWARD -o eth0 -j ACCEPT 2>/dev/null ||
            iptables -A FORWARD -o eth0 -j ACCEPT
    fi
    mkdir -p "$base/state/artifacts"
    python3 - "$base/state/host.json" <<'PY'
import json, pathlib, sys
dns = []
for line in pathlib.Path('/etc/resolv.conf').read_text().splitlines():
    parts = line.split()
    if len(parts) >= 2 and parts[0] == 'nameserver' and not parts[1].startswith('127.'):
        dns.append(parts[1])
cfg = {'reserve_mib': 128}
if dns:
    cfg['dns'] = dns
pathlib.Path(sys.argv[1]).write_text(json.dumps(cfg) + '\n')
PY
    for artifact in firecracker vmlinux kernel-modules.tar.gz; do
        cp "/nested-input/$artifact" "$base/state/artifacts/$artifact"
        sha256sum "$base/state/artifacts/$artifact" > "$base/state/artifacts/$artifact.sha256"
    done
    # Let the inner VM use elastic memory up to the outer guest's RAM (no --plug 0).
    cli pull /nested-input/docker-dind.tar --tag nested-docker --vcpus 1
    # Local Unix socket access via `flexvm exec` does not need 4096-bit TLS cert generation.
    cli run -d --name docker-vm -e DOCKER_TLS_CERTDIR= nested-docker
    ready=false
    for _ in $(seq 1 180); do
        if docker info >/dev/null 2>&1; then ready=true; break; fi
        sleep 1
    done
    if ! $ready; then
        cli logs --tail 100 docker-vm >&2 || true
        echo 'Docker inside nested FlexVM did not become ready within 180 seconds' >&2
        exit 1
    fi
    docker info
    test "$(docker info --format '{{.Driver}}')" = overlay2
    test "$(docker info --format '{{.CgroupVersion}}')" = 2

    # Build a local BusyBox image inside the inner DinD VM to avoid registry throttling.
    dexec sh -ec '
        root=/tmp/nested-base-root
        rm -rf "$root"
        mkdir -p "$root/bin" "$root/lib" "$root/tmp" /tmp/nested-bind
        chmod 1777 "$root/tmp"
        cp /bin/busybox "$root/bin/"
        for library in /lib/ld-musl-*.so.1 /lib/libc.musl-*.so.1; do
            if [ -e "$library" ]; then cp -L "$library" "$root/lib/"; fi
        done
        test -f "$root"/lib/ld-musl-*.so.1
        for applet in sh cat wget nc sleep printf mv test; do ln -s busybox "$root/bin/$applet"; done
        printf "#!/bin/sh\nprintf '\''HTTP/1.0 200 OK\\r\\n\\r\\n'\''\ncat /data/marker\n" > "$root/bin/serve"
        chmod 755 "$root/bin/serve"
        tar -C "$root" -cf /tmp/nested-base.tar .
        docker import /tmp/nested-base.tar flexvm-nested-base:local
        rm -rf "$root" /tmp/nested-base.tar
    '

    # Verify delegated cgroup v2 limits, named volume, and bind mount inside the nested VM.
    docker volume create nested-data
    docker run --rm --memory=64m --cpus=.5 --pids-limit=64 \
        -e "NONCE=$nonce" -v nested-data:/data -v /tmp/nested-bind:/bind \
        flexvm-nested-base:local sh -ec '
            test "$(cat /sys/fs/cgroup/memory.max)" = 67108864
            test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
            test "$(cat /sys/fs/cgroup/pids.max)" = 64
            printf "%s" "$NONCE" >/data/marker
            printf "%s" "$NONCE" >/bind/marker
        '
    test "$(dexec cat /tmp/nested-bind/marker)" = "$nonce"

    # Verify uncached BuildKit image build inside the nested FlexVM.
    dexec sh -ec '
        mkdir -p /tmp/nested-build-ctx
        printf "FROM flexvm-nested-base:local\nRUN printf buildkit-nested-ok >/built\nCMD [\"/bin/cat\", \"/built\"]\n" \
            >/tmp/nested-build-ctx/Dockerfile
        DOCKER_BUILDKIT=1 docker build --no-cache --progress=plain -t flexvm-nested-build /tmp/nested-build-ctx
        test "$(docker run --rm flexvm-nested-build)" = buildkit-nested-ok
    '

    # Start a live container on a custom bridge with published port, RAM cookie, and counter.
    docker network create nested-net
    docker run -d --name nested-srv --network nested-net -p 18080:8080 -v nested-data:/data \
        flexvm-nested-base:local sh -ec '
            cookie=$(cat /proc/sys/kernel/random/uuid)
            nc -lk -p 8080 -e /bin/serve &
            counter=0
            while :; do
                counter=$((counter + 1))
                printf "%s %s\n" "$cookie" "$counter" >/tmp/probe.new
                mv /tmp/probe.new /tmp/probe
                sleep .2
            done
        '
    ready_srv=false
    for _ in $(seq 1 60); do
        if dexec wget -qO /dev/null http://127.0.0.1:18080/marker 2>/dev/null &&
           dexec docker exec nested-srv test -s /tmp/probe 2>/dev/null; then
            ready_srv=true
            break
        fi
        sleep .5
    done
    if ! $ready_srv; then
        docker logs nested-srv >&2 || true
        exit 1
    fi
    docker inspect --format '{{.State.Pid}}' nested-srv > "$base/srv-pid"
    dexec docker exec nested-srv cat /tmp/probe > "$base/probe"
    test -s "$base/srv-pid"
    test -s "$base/probe"

    # Exercise inner FlexVM pause/unpause and stop/start (snapshot/restore).
    cli pause docker-vm
    cli unpause docker-vm
    cli stop docker-vm
    cli start docker-vm
    check_live_container
    cli ps --json > "$base/initial-vms.json"
    ;;
verify)
    traffic_control
    check_live_container
    cli ps --json
    printf 'NESTED_FLEXVM_DOCKER_PHASE_OK %s %s\n' "$phase" "$(cat "$base/probe-now")"
    ;;
*) exit 2 ;;
esac
