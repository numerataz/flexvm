#!/bin/sh
# Run inside the software VM; vfs avoids overlay-on-overlay assumptions.
set -eu
mkdir -p /run /tmp/flexvm-bind
export DOCKER_HOST=unix:///run/docker.sock
export DOCKER_TLS_CERTDIR=
dockerd --host="$DOCKER_HOST" --storage-driver=vfs > /tmp/dockerd.log 2>&1 &
daemon=$!
cleanup() {
    status=$?
    trap - EXIT
    kill "$daemon" 2>/dev/null || true
    wait "$daemon" 2>/dev/null || true
    cat /tmp/dockerd.log || true
    exit "$status"
}
trap cleanup EXIT
for attempt in $(seq 1 120); do
    if docker info >/dev/null 2>&1; then break; fi
    kill -0 "$daemon" || exit 12
    sleep 1
done
docker info
test "$(docker info --format '{{.Driver}}')" = vfs
test "$(docker info --format '{{.CgroupVersion}}')" = 2
# Import the guest's BusyBox and musl runtime instead of depending on a second
# registry pull from inside the VM (public registries can rate-limit CI).
root=/tmp/container-root
mkdir -p "$root/bin" "$root/lib"
cp /bin/busybox "$root/bin/"
for library in /lib/ld-musl-*.so.1 /lib/libc.musl-*.so.1; do
    if [ -e "$library" ]; then cp -L "$library" "$root/lib/"; fi
done
test -f "$root"/lib/ld-musl-*.so.1
for applet in sh cat wget; do ln -s busybox "$root/bin/$applet"; done
image=flexvm-software-base:local
tar -C "$root" -cf /tmp/software-base.tar .
docker import /tmp/software-base.tar "$image"
docker volume create software-data
docker run --rm --memory=64m --cpus=.5 --pids-limit=64 -v software-data:/data -v /tmp/flexvm-bind:/bind "$image" sh -ec '
 test "$(cat /sys/fs/cgroup/memory.max)" = 67108864
 test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
 test "$(cat /sys/fs/cgroup/pids.max)" = 64
 echo software-docker >/data/marker
 echo software-bind >/bind/marker
 wget -qO /dev/null http://example.com
'
test "$(cat /tmp/flexvm-bind/marker)" = software-bind
test "$(docker run --rm -v software-data:/data "$image" cat /data/marker)" = software-docker
echo FLEXVM_SOFTWARE_DOCKER_PASSED
