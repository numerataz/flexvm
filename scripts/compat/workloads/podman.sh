#!/bin/sh
# Guest workload for compat.py: stock Ubuntu packages, rootful and rootless Podman.
set -eu
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-compat-$nonce
user=fc$(printf %.12s "$nonce")
cgroup=/sys/fs/cgroup/$user
image=docker.io/library/busybox:1.36

pod() {
    if [ "$mode" = rootless ]; then
        sh -ec 'echo 0 >"$1"; user=$2; runtime=$3; shift 3
            exec runuser -u "$user" -- env XDG_RUNTIME_DIR="$runtime" podman --cgroup-manager=cgroupfs "$@"' \
            sh "$cgroup/session/cgroup.procs" "$user" "/run/user/$uid" "$@"
    else
        podman --cgroup-manager=cgroupfs "$@"
    fi
}

case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates podman uidmap fuse-overlayfs slirp4netns curl crun netavark aardvark-dns
    mkdir -p "$base" /etc/containers
    # The guest root itself is overlayfs. FUSE supplies an ordinary supported
    # overlay backing for both runtimes without falling back to the vfs driver.
    cat > /etc/containers/storage.conf <<'EOF'
[storage]
driver = "overlay"
[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
EOF
    useradd -m -s /bin/sh "$user"
    uid=$(id -u "$user")
    grep -q "^$user:" /etc/subuid
    grep -q "^$user:" /etc/subgid
    install -d -m 700 -o "$user" -g "$user" "/run/user/$uid"
    # Ordinary cgroup-v2 delegation for a rootless session without a service manager.
    mkdir -p "$cgroup/session"
    echo '+cpu +memory +pids' > "$cgroup/cgroup.subtree_control"
    chown -R "$user:$user" "$cgroup"
    echo "$uid" > "$base/uid"
    podman --version
    crun --version
    fuse-overlayfs --version
    for mode in rootful rootless; do
        if [ "$mode" = rootless ]; then pod unshare cat /proc/self/uid_map; fi
        test "$(pod info --format '{{.Store.GraphDriverName}}')" = overlay
        pod pull "$image"
        parent=/libpod_parent
        port=18081
        if [ "$mode" = rootless ]; then parent=/$user; port=18082; fi
        pod network create compat-net
        bind=$base/bind-$mode
        mkdir "$bind"
        if [ "$mode" = rootless ]; then chown "$user:$user" "$bind"; chmod 755 "$base"; fi
        pod run --rm --cgroup-parent="$parent" -v "$bind:/bind" "$image" sh -ec 'echo "$1" >/bind/marker' sh "$nonce"
        test "$(cat "$bind/marker")" = "$nonce"
        pod volume create compat-data
        pod run --rm --cgroup-parent="$parent" -v compat-data:/data "$image" sh -ec 'echo "$1" >/data/marker' sh "$nonce"
        # Verify real controller enforcement, DNS and outbound HTTP.
        pod run --rm --cgroup-parent="$parent" --memory=64m --cpus=.5 --pids-limit=64 "$image" sh -ec '
            test "$(cat /sys/fs/cgroup/memory.max)" = 67108864
            test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
            test "$(cat /sys/fs/cgroup/pids.max)" = 64
            wget -qO /dev/null http://example.com
        '
        context=$base/build-$mode
        mkdir "$context"
        printf 'FROM %s\nRUN echo build-ok >/built\nCMD ["cat", "/built"]\n' "$image" > "$context/Containerfile"
        if [ "$mode" = rootless ]; then chown -R "$user:$user" "$context"; chmod 755 "$base"; fi
        pod build --cgroup-parent="$parent" -t localhost/flexvm-compat "$context"
        test "$(pod run --rm --cgroup-parent="$parent" localhost/flexvm-compat)" = build-ok
        pod run -d --name compat-server --network compat-net --cgroup-parent="$parent" -p "$port:8080" -v compat-data:/data "$image" sh -ec '
            mkdir /www; cp /data/marker /www/index.html; exec httpd -f -p 8080 -h /www
        '
        test "$(pod run --rm --network compat-net --cgroup-parent="$parent" "$image" wget -qO- http://compat-server:8080)" = "$nonce"
        pod exec compat-server cat /proc/1/stat > "$base/process-$mode"
        echo "$mode prepared"
    done
    ;;
verify)
    uid=$(cat "$base/uid")
    for mode in rootful rootless; do
        port=18081
        if [ "$mode" = rootless ]; then port=18082; fi
        test "$(pod exec compat-server cat /data/marker)" = "$nonce"
        test "$(cat "$base/bind-$mode/marker")" = "$nonce"
        # Compare PID and starttime, allowing CPU counters/state to change.
        before=$(awk '{print $1, $22}' "$base/process-$mode")
        after=$(pod exec compat-server cat /proc/1/stat | awk '{print $1, $22}')
        test "$before" = "$after"
        response=$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 "http://127.0.0.1:$port")
        test "$response" = "$nonce"
        echo "$mode: live process, named volume and published port passed after $phase"
    done
    ;;
*) echo "unknown workload step: $step" >&2; exit 2 ;;
esac
