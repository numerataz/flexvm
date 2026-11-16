#!/bin/sh
# Guest-only standalone containerd, nerdctl/CNI and BuildKit acceptance.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-containerd-$nonce
source_image=public.ecr.aws/docker/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
image=localhost/flexvm-compat-base:verified
nerd() { nerdctl --snapshotter=native --cgroup-manager=cgroupfs "$@"; }
build() {
    previous=0
    if [ -f "$base/build-counter" ]; then previous=$(cat "$base/build-counter"); fi
    epoch=$((previous+1))
    # Changing this used ARG forces RUN while preserving the persistent cache
    # mount. BuildKit's global --no-cache also prunes cache-mount identities.
    buildctl --addr unix:///run/buildkit/buildkitd.sock build --frontend dockerfile.v0 \
        --local context="$base/context" --local dockerfile="$base/context" \
        --secret id=token,src="$base/secret" --opt "build-arg:RUN_EPOCH=$epoch" \
        --output "type=oci,dest=$base/built.tar" >"$base/build-$phase.log" 2>&1 || {
            cat "$base/build-$phase.log"; return 1;
        }
    cat "$base/build-$phase.log"
    nerd load -i "$base/built.tar"
    built=$(tar -xOf "$base/built.tar" index.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["manifests"][0]["digest"])')
    # OCI archives can name the imported image by its digest.
    result=$(nerd run --rm "$built" cat /built)
    test "$result" = "$epoch"
    echo "$result" > "$base/build-counter"
    nerd run --rm "$built" sh -ec 'test ! -e /run/secrets/token; test "$(cat /secret-check)" = ok'
}
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates curl iptables python3
    mkdir -p "$base" /etc/containerd /run/containerd /run/buildkit
    case $(uname -m) in
        x86_64) arch=amd64; digest=1f12c1a5840744fdf7029483c55a69813d44aa2ec1ef879d52d81ff6a3049ecd ;;
        aarch64) arch=arm64; digest=fe0ef0e9840ee8932640e6058f84b7fa98050f9726e44af44883a5b804ae830e ;;
        *) exit 2 ;;
    esac
    curl --fail --location --retry 2 -o "$base/nerdctl.tar.gz" "https://github.com/containerd/nerdctl/releases/download/v2.4.2/nerdctl-full-2.4.2-linux-$arch.tar.gz"
    printf '%s  %s\n' "$digest" "$base/nerdctl.tar.gz" | sha256sum --check --strict
    tar -xzf "$base/nerdctl.tar.gz" -C /usr/local
    containerd --version; nerdctl --version; runc --version; buildkitd --version
    # Native snapshotter supports this overlay-backed VM root explicitly.
    # This is a normal containerd snapshotter, with no hidden overlay fallback.
    cat > /etc/containerd/config.toml <<'CONFIG'
version = 3
disabled_plugins = ["io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]
[[plugins."io.containerd.transfer.v1.local".unpack_config]]
  platform = "linux"
  snapshotter = "native"
CONFIG
    nohup containerd --config /etc/containerd/config.toml > "$base/containerd.log" 2>&1 </dev/null &
    echo $! > "$base/containerd.pid"
    ready=false
    for attempt in $(seq 1 100); do
        if ctr version >/dev/null 2>&1; then ready=true; break; fi
        sleep .1
    done
    if ! "$ready"; then cat "$base/containerd.log"; exit 3; fi
    ctr plugins ls
    ctr plugins ls | grep 'io.containerd.snapshotter.v1 .*native .*ok'
    nohup buildkitd --oci-worker=false --containerd-worker=true --containerd-worker-snapshotter=native \
        > "$base/buildkitd.log" 2>&1 </dev/null &
    echo $! > "$base/buildkitd.pid"
    ready=false
    for attempt in $(seq 1 100); do
        if buildctl debug workers > "$base/workers" 2>&1; then ready=true; break; fi
        sleep .1
    done
    if ! "$ready"; then cat "$base/buildkitd.log"; exit 3; fi
    buildctl debug workers --verbose
    nerd pull "$source_image"
    ctr images tag "$source_image" "$image"
    ctr images ls
    nerd image inspect "$image"
    nerd network create compat-net
    nerd volume create compat-data
    mkdir "$base/bind"
    echo "$nonce" > "$base/bind/marker"
    nerd run --rm -v compat-data:/data "$image" sh -ec 'echo "$1" >/data/marker' sh "$nonce"
    nerd run --rm --memory=128m --cpus=.5 --pids-limit=64 "$image" sh -ec '
        test "$(cat /sys/fs/cgroup/memory.max)" = 134217728
        test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
        test "$(cat /sys/fs/cgroup/pids.max)" = 64
        wget -qO /dev/null http://example.com
    '
    nerd run -d --name compat-server --network compat-net -p 18084:8080 \
        -v compat-data:/data -v "$base/bind:/bind:ro" "$image" sh -ec '
        test "$(cat /bind/marker)" = "$1"; test "$(cat /data/marker)" = "$1"
        mkdir /www; cookie=$(od -An -tx1 -N16 /dev/urandom | tr -d " \n")
        echo "$cookie" >/www/cookie; httpd -f -p 8080 -h /www &
        i=0; while :; do i=$((i+1)); echo "$i" >/www/counter.tmp; mv /www/counter.tmp /www/counter; sleep .1; done
    ' sh "$nonce"
    curl --fail --silent --show-error --retry 20 --retry-connrefused --retry-delay 1 http://127.0.0.1:18084/cookie > "$base/cookie"
    nerd exec compat-server cat /proc/1/stat > "$base/process"
    response=$(nerd run --rm --network compat-net "$image" wget -qO- http://compat-server:8080/cookie)
    test "$response" = "$(cat "$base/cookie")"
    mkdir "$base/context"
    printf '%s' "$nonce" > "$base/secret"
    cat > "$base/context/Dockerfile" <<DOCKERFILE
FROM $source_image
ARG RUN_EPOCH
RUN --mount=type=cache,id=flexvm-compat-counter,target=/cache --mount=type=secret,id=token,required=true \\
    test -n "\$RUN_EPOCH" && test "\$(cat /run/secrets/token)" = "$nonce" && echo ok >/secret-check && \\
    i=0; if [ -f /cache/counter ]; then i=\$(cat /cache/counter); fi; \\
    i=\$((i+1)); echo "\$i" >/cache/counter; cp /cache/counter /built
DOCKERFILE
    build
    for daemon in containerd buildkitd; do
        cat "/proc/$(cat "$base/$daemon.pid")/stat" > "$base/$daemon.process"
    done
    ;;
verify)
    for daemon in containerd buildkitd; do
        before=$(awk '{print $1, $22}' "$base/$daemon.process")
        after=$(awk '{print $1, $22}' "/proc/$(cat "$base/$daemon.pid")/stat")
        test "$before" = "$after"
    done
    before=$(awk '{print $1, $22}' "$base/process")
    after=$(nerd exec compat-server cat /proc/1/stat | awk '{print $1, $22}')
    test "$before" = "$after"
    nerd exec compat-server sh -ec 'test "$(cat /data/marker)" = "$1"; test "$(cat /bind/marker)" = "$1"' sh "$nonce"
    response=$(curl --fail --silent --show-error http://127.0.0.1:18084/cookie)
    test "$response" = "$(cat "$base/cookie")"
    response=$(nerd run --rm --network compat-net "$image" wget -qO- http://compat-server:8080/cookie)
    test "$response" = "$(cat "$base/cookie")"
    python3 - <<'PROGRESS'
import time, urllib.request

def counter():
    with urllib.request.urlopen('http://127.0.0.1:18084/counter', timeout=3) as response:
        return int(response.read())
initial = counter()
deadline = time.monotonic() + 15
while True:
    current = counter()
    if current >= initial + 2:
        break
    assert time.monotonic() < deadline, 'container stopped making fresh progress'
    time.sleep(.05)
print('containerd fresh counter:', initial, '->', current)
PROGRESS
    build
    echo "containerd/nerdctl CNI, volumes, process state, BuildKit secret/cache/build passed after $phase"
    ;;
*) exit 2 ;;
esac
