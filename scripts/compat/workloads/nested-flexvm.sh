#!/bin/sh
# Run the normal native FlexVM CLI inside the software VM's ordinary KVM guest.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-nested-$nonce
cli() { /nested-input/flexvm --state "$base/state" --run "$base/run" "$@"; }
traffic_control() {
    # Isolate the real netlink operations; a kernel without any one facility fails.
    unshare --net /bin/sh -ec '
        tc qdisc add dev lo clsact
        tc filter add dev lo ingress protocol all pref 1 bpf da bytecode "1,6 0 0 0,"
        tc qdisc add dev lo root handle 1: plug
        tc qdisc change dev lo root handle 1: plug release_indefinite
        tc -j qdisc show dev lo'
}
case $step in
prepare)
    if ! (command -v mkfs.ext4 >/dev/null && command -v debugfs >/dev/null &&
          command -v python3 >/dev/null && command -v tc >/dev/null && command -v unshare >/dev/null); then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends e2fsprogs python3 iproute2 util-linux
    fi
    traffic_control
    test -c /dev/kvm
    test -c /dev/net/tun
    mkdir -p "$base/state/artifacts"
    printf '%s\n' '{"reserve_mib":128}' > "$base/state/host.json"
    for artifact in firecracker vmlinux kernel-modules.tar.gz; do
        cp "/nested-input/$artifact" "$base/state/artifacts/$artifact"
        sha256sum "$base/state/artifacts/$artifact" > "$base/state/artifacts/$artifact.sha256"
    done
    cli pull /nested-input/child.tar --tag nested-child --mem 128 --plug 0 --vcpus 1
    cli run -d --name child nested-child
    for attempt in $(seq 1 100); do
        if cli exec child /state-probe status > "$base/initial"; then break; fi
        sleep .1
    done
    test -s "$base/initial"
    # Exercise the native child's plug queue as well as the outer emulator.
    cli pause child
    cli unpause child
    cli ps --json > "$base/initial-vms.json"
    ;;
verify)
    traffic_control
    cli exec child /state-probe status > "$base/current"
    python3 - "$base/initial" "$base/current" <<'PY'
from pathlib import Path
import sys
before, current = [list(map(int, Path(name).read_text().split())) for name in sys.argv[1:]]
assert len(before) == len(current) == 5, (before, current)
assert before[:3] == current[:3], ('child identity/RAM changed', before, current)
PY
    # Fresh observations after every resume must advance both CPU work and time.
    sleep .2
    cli exec child /state-probe status > "$base/next"
    python3 - "$base/current" "$base/next" <<'PY'
from pathlib import Path
import sys
before, current = [list(map(int, Path(name).read_text().split())) for name in sys.argv[1:]]
assert before[:3] == current[:3], (before, current)
assert current[3] > before[3] and current[4] > before[4], ('child stopped advancing', before, current)
print('NESTED_FLEXVM_CONTINUITY', *current)
PY
    cli ps --json
    ;;
*) exit 2 ;;
esac
