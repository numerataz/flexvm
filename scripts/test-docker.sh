#!/usr/bin/env bash
# Registry-backed Docker smoke test on a KVM host with guest DNS and outbound routing/NAT.
# Usage: sudo FLEXVM_BIN=target/release/flexvm scripts/test-docker.sh
# FLEXVM_STATE_DIR selects another state directory. Registry layers remain cached.
set -euo pipefail

fv=("${FLEXVM_BIN:-flexvm}")
if [ -n "${FLEXVM_STATE_DIR:-}" ]; then fv+=(--state "$FLEXVM_STATE_DIR"); fi
vm="docker-test-$(cat /proc/sys/kernel/random/uuid)"
started=false
pulled=false
image="$vm-image"
cleanup() {
    status=$?
    trap - EXIT
    if $started; then
        if [ "$status" != 0 ]; then
            "${fv[@]}" exec "$vm" docker logs server >&2 || true
            "${fv[@]}" logs --tail 100 "$vm" >&2 || true
        fi
        "${fv[@]}" rm -f "$vm" || status=1
    fi
    if $pulled; then "${fv[@]}" rmi "$image" || status=1; fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"${fv[@]}" pull docker:27-dind --tag "$image" --vcpus 2 --max 4096
pulled=true
"${fv[@]}" run -d --name "$vm" "$image"
started=true
docker() { "${fv[@]}" exec "$vm" docker "$@"; }
ready=false
for _ in $(seq 1 60); do
    if docker info >/dev/null 2>&1; then ready=true; break; fi
    sleep 1
done
if ! $ready; then echo 'Docker did not become ready within 60 seconds' >&2; exit 1; fi
[ "$(docker info --format '{{.Driver}}')" = overlay2 ]
docker run --rm hello-world

# Default bridge: outbound DNS/HTTP and actual cgroup limits inside the container.
docker run --rm --memory=64m --cpus=.5 --pids-limit=64 alpine:3.21 sh -ec '
    wget -qO /dev/null http://example.com
    test "$(cat /sys/fs/cgroup/memory.max)" = 67108864
    test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
    test "$(cat /sys/fs/cgroup/pids.max)" = 64
'

# A custom bridge's embedded DNS, communication between containers, and published ports.
docker network create smoke-net
docker run -d --name server --network smoke-net -p 18080:8080 busybox:1.36 sh -ec '
    mkdir -p /tmp/www; echo bridge-ok >/tmp/www/index.html; exec httpd -f -p 8080 -h /tmp/www
'
docker exec server sh -ec '
    for _ in $(seq 1 30); do
        if wget -qO /dev/null http://127.0.0.1:8080; then exit 0; fi
        sleep 1
    done
    exit 1
'
[ "$(docker run --rm --network smoke-net alpine:3.21 wget -qO- http://server:8080)" = bridge-ok ]
[ "$("${fv[@]}" exec "$vm" wget -qO- http://127.0.0.1:18080)" = bridge-ok ]

docker volume create smoke-data
docker run --rm -v smoke-data:/data alpine:3.21 sh -ec 'echo volume-ok >/data/marker'
printf 'FROM alpine:3.21\nRUN echo build-ok >/built\nCMD ["cat", "/built"]\n' |
    "${fv[@]}" exec -i "$vm" docker build -t flexvm-smoke -
[ "$(docker run --rm flexvm-smoke)" = build-ok ]

# Guest mounts, a live container, and named volume data all travel with the VM's memory.
"${fv[@]}" stop "$vm"
"${fv[@]}" start "$vm"
[ "$(docker exec server wget -qO- http://127.0.0.1:8080)" = bridge-ok ]
[ "$(docker run --rm -v smoke-data:/data alpine:3.21 cat /data/marker)" = volume-ok ]
echo 'PASS: Docker overlay2, networking, limits, build, volume and suspend/resume'
