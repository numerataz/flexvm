#!/bin/sh
# Upstream rootless containerd/nerdctl and standalone BuildKit user services.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-rootless-containerd-$nonce
user=fn$(printf %.12s "$nonce")
source_image=public.ecr.aws/docker/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
image=localhost/flexvm-rootless-base:verified
as_user() { runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" "$@"; }
nerd() { as_user nerdctl --snapshotter=native --cgroup-manager=systemd "$@"; }
buildctl_user() { as_user buildctl --addr "unix:///run/user/$uid/buildkit/buildkitd.sock" "$@"; }
diagnostics() {
    status=$?
    trap - EXIT
    if [ "$status" != 0 ] && [ -n "${uid:-}" ]; then
        journalctl "_UID=$uid" _SYSTEMD_USER_UNIT=containerd.service _SYSTEMD_USER_UNIT=buildkit.service --no-pager -n 120 || true
        as_user systemctl --user status containerd.service buildkit.service --no-pager --full || true
        dmesg | tail -50 || true
    fi
    exit "$status"
}
trap diagnostics EXIT
load_base() {
    if [ -e /nested-input/busybox.tar ] || [ -e /nested-input/busybox.json ] || [ -e /nested-input/busybox-oci ]; then
        python3 - "$source_image" > "$base/base-manifest" <<'PYFIXTURE'
from pathlib import Path
import json, platform, runpy, sys

root = Path('/nested-input')
fixture = runpy.run_path(str(root / 'workload-fixture.py'))
arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
identity = fixture['validate_cache'](root / 'busybox-oci', arch)
if identity['source'] != sys.argv[1]:
    raise ValueError('fixture source differs from the pinned BusyBox reference')
metadata = json.loads((root / 'busybox.json').read_text())
if any(metadata[key] != expected for key, expected in identity.items()):
    raise ValueError('seeded BusyBox metadata differs from the pinned OCI layout')
archive = fixture['validate_archive'](root / 'busybox.tar', identity)
if archive != 'sha256:' + metadata['archive_sha256']:
    raise ValueError('seeded BusyBox archive differs from the verified export')
print(identity['manifest_digest'])
PYFIXTURE
        seed_tag=docker.io/flexvm/busybox:compat
        nerd load -i /nested-input/busybox.tar
        nerd save "$seed_tag" > "$base/imported-image.tar"
        python3 /nested-input/verify-fixture-import.py --archive "$base/imported-image.tar" --metadata /nested-input/busybox.json
        rm "$base/imported-image.tar"
        nerd tag "$seed_tag" "$image"
        build_source=fixture-base
    else
        nerd pull "$source_image"
        nerd tag "$source_image" "$image"
        build_source=$source_image
    fi
}
build() {
    free -m
    epoch=1
    if [ -f "$base/build-counter" ]; then epoch=$(($(cat "$base/build-counter")+1)); fi
    set --
    if [ -f "$base/base-manifest" ]; then
        manifest=$(cat "$base/base-manifest")
        set -- --oci-layout fixture=/nested-input/busybox-oci --opt "context:fixture-base=oci-layout://fixture@$manifest"
    fi
    buildctl_user build "$@" --frontend dockerfile.v0 --local "context=$base/context" --local "dockerfile=$base/context" \
        --secret "id=token,src=$base/secret" --opt "build-arg:RUN_EPOCH=$epoch" \
        --output "type=oci,dest=$base/build/built.tar"
    nerd load -i "$base/build/built.tar"
    built=$(tar -xOf "$base/build/built.tar" index.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["manifests"][0]["digest"])')
    test "$(nerd run --rm "$built" cat /built)" = "$epoch"
    nerd run --rm "$built" sh -ec 'test ! -e /run/secrets/token; test "$(cat /secret-check)" = ok'
    printf '%s\n' "$epoch" > "$base/build-counter"
}
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates curl iptables uidmap slirp4netns fuse-overlayfs \
        dbus dbus-user-session libpam-systemd passwd python3
    systemctl start dbus.service systemd-logind.service
    mkdir -p "$base" /etc/containerd
    chmod 755 "$base"
    case $(uname -m) in
        x86_64) arch=amd64; digest=1f12c1a5840744fdf7029483c55a69813d44aa2ec1ef879d52d81ff6a3049ecd ;;
        aarch64) arch=arm64; digest=fe0ef0e9840ee8932640e6058f84b7fa98050f9726e44af44883a5b804ae830e ;;
        *) exit 2 ;;
    esac
    curl --fail --location --retry 2 -o "$base/nerdctl.tar.gz" "https://github.com/containerd/nerdctl/releases/download/v2.4.2/nerdctl-full-2.4.2-linux-$arch.tar.gz"
    printf '%s  %s\n' "$digest" "$base/nerdctl.tar.gz" | sha256sum --check --strict
    tar -xzf "$base/nerdctl.tar.gz" -C /usr/local
    rm "$base/nerdctl.tar.gz"
    containerd --version; nerdctl --version; runc --version; rootlesskit --version; buildkitd --version
    useradd -m -s /bin/sh "$user"
    uid=$(id -u "$user")
    printf '%s\n' "$uid" > "$base/uid"
    grep -q "^$user:" /etc/subuid
    grep -q "^$user:" /etc/subgid
    loginctl enable-linger "$user"
    systemctl start "user@$uid.service"
    install -d -m 755 -o "$user" -g "$user" "/home/$user/.config" "/home/$user/.config/containerd" "/home/$user/.config/buildkit" \
        "$base/context" "$base/build" "$base/bind"
    # Both snapshotters are explicit ordinary choices for the overlay-backed VM root.
    cat > "/home/$user/.config/containerd/config.toml" <<'CONFIG'
version = 3
disabled_plugins = ["io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]
[[plugins."io.containerd.transfer.v1.local".unpack_config]]
  platform = "linux"
  snapshotter = "native"
CONFIG
    cat > "/home/$user/.config/buildkit/buildkitd.toml" <<'CONFIG'
[worker.oci]
  snapshotter = "fuse-overlayfs"
CONFIG
    chown -R "$user:$user" "/home/$user/.config"
    as_user containerd-rootless-setuptool.sh install
    as_user containerd-rootless-setuptool.sh install-buildkit
    as_user systemctl --user set-property buildkit.service MemoryMax=536870912 TasksMax=256 CPUQuota=100%
    as_user systemctl --user show containerd.service --property=Delegate --property=MainPID
    test "$(as_user systemctl --user show containerd.service --property=Delegate --value)" = yes
    buildctl_user debug workers --verbose > "$base/workers"
    cat "$base/workers"
    grep 'org.mobyproject.buildkit.worker.snapshotter:.*fuse-overlayfs' "$base/workers"
    nerd info
    load_base
    nerd image inspect "$image"
    nerd network create compat-net
    nerd volume create compat-data
    nerd run --rm -v compat-data:/data -v "$base/bind:/bind" "$image" sh -ec 'echo "$1" >/data/marker; echo "$1" >/bind/marker' sh "$nonce"
    nerd run --rm --network compat-net --memory=128m --cpus=.5 --pids-limit=64 "$image" sh -ec '
        test "$(cat /sys/fs/cgroup/memory.max)" = 134217728
        test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
        test "$(cat /sys/fs/cgroup/pids.max)" = 64
        wget -qO /dev/null http://example.com'
    nerd run -d --name compat-server --network compat-net --memory=128m --cpus=.5 --pids-limit=64 -p 18086:8080 -v compat-data:/data -v "$base/bind:/bind:ro" "$image" sh -ec '
        mkdir /www; cp /data/marker /www/index.html; exec httpd -f -p 8080 -h /www'
    nerd exec compat-server cat /proc/1/stat > "$base/process"
    printf '%s\n' "$nonce" > "$base/secret"
    cat > "$base/context/Dockerfile" <<EOF
FROM $build_source
ARG RUN_EPOCH
RUN --mount=type=cache,target=/cache --mount=type=secret,id=token \\
    set -eu; test -s /run/secrets/token; echo ok >/secret-check; \\
    previous=0; if [ -f /cache/counter ]; then previous=\$(cat /cache/counter); fi; \\
    next=\$((previous+1)); test "\$next" = "\$RUN_EPOCH"; echo "\$next" >/cache/counter; cp /cache/counter /built
EOF
    chmod 644 "$base/secret"
    build
    ;;
verify)
    uid=$(cat "$base/uid")
    as_user systemctl --user is-active --quiet containerd.service buildkit.service
    test "$(nerd exec compat-server cat /data/marker)" = "$nonce"
    test "$(nerd exec compat-server cat /bind/marker)" = "$nonce"
    before=$(awk '{print $1, $22}' "$base/process")
    after=$(nerd exec compat-server cat /proc/1/stat | awk '{print $1, $22}')
    test "$before" = "$after"
    nerd exec compat-server sh -ec '
        test "$(cat /sys/fs/cgroup/memory.max)" = 134217728
        test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
        test "$(cat /sys/fs/cgroup/pids.max)" = 64'
    test "$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:18086)" = "$nonce"
    test "$(nerd run --rm --network compat-net "$image" wget -qO- http://compat-server:8080)" = "$nonce"
    group=$(as_user systemctl --user show buildkit.service --property=ControlGroup --value)
    test "$(cat "/sys/fs/cgroup$group/memory.max")" = 536870912
    test "$(cat "/sys/fs/cgroup$group/pids.max")" = 256
    test "$(cat "/sys/fs/cgroup$group/cpu.max")" = '100000 100000'
    build
    printf 'ROOTLESS_CONTAINERD_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
