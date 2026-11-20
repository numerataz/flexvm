#!/bin/sh
# Stock Podman socket activation and systemd-managed rootless container scopes.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-rootless-podman-$nonce
user=fp$(printf %.12s "$nonce")
image=public.ecr.aws/docker/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
as_user() { runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" "$@"; }
pod() { as_user podman --remote --url "unix:///run/user/$uid/podman/podman.sock" "$@"; }
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates podman uidmap fuse-overlayfs slirp4netns curl crun \
        netavark aardvark-dns iptables dbus dbus-user-session libpam-systemd passwd
    systemctl start dbus.service systemd-logind.service
    mkdir -p "$base/context" "$base/bind"
    chmod 755 "$base"
    useradd -m -s /bin/sh "$user"
    uid=$(id -u "$user")
    printf '%s\n' "$uid" > "$base/uid"
    grep -q "^$user:" /etc/subuid
    grep -q "^$user:" /etc/subgid
    loginctl enable-linger "$user"
    systemctl start "user@$uid.service"
    install -d -m 755 -o "$user" -g "$user" "/home/$user/.config" "/home/$user/.config/containers"
    cat > "/home/$user/.config/containers/storage.conf" <<EOF
[storage]
driver = "overlay"
runroot = "/run/user/$uid/containers"
graphroot = "/home/$user/.local/share/containers/storage"
[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
EOF
    cat > "/home/$user/.config/containers/containers.conf" <<'EOF'
[network]
network_backend = "netavark"
[engine]
cgroup_manager = "systemd"
EOF
    chown -R "$user:$user" "/home/$user/.config" "$base/context" "$base/bind"
    as_user systemctl --user enable --now podman.socket
    pod version
    pod info
    test "$(pod info --format '{{.Store.GraphDriverName}}')" = overlay
    test "$(pod info --format '{{.Host.CgroupManager}}')" = systemd
    test "$(pod info --format '{{.Host.Security.Rootless}}')" = true
    pod pull "$image"
    pod image inspect "$image"
    pod network create compat-net
    pod run --rm --network compat-net "$image" wget -qO /dev/null https://github.com/robots.txt
    pod volume create compat-data
    pod run --rm -v compat-data:/data -v "$base/bind:/bind" "$image" sh -ec 'echo "$1" >/data/marker; echo "$1" >/bind/marker' sh "$nonce"
    pod run -d --name compat-server --network compat-net --memory=64m --cpus=.5 --pids-limit=64 -p 18087:8080 \
        -v compat-data:/data -v "$base/bind:/bind:ro" "$image" sh -ec '
        mkdir /www; cp /data/marker /www/index.html; exec httpd -f -p 8080 -h /www'
    pod exec compat-server cat /proc/1/stat > "$base/process"
    printf 'FROM %s\nRUN echo rootless-service-build >/built\n' "$image" > "$base/context/Containerfile"
    pod build -t localhost/flexvm-rootless-built "$base/context"
    test "$(pod run --rm localhost/flexvm-rootless-built cat /built)" = rootless-service-build
    dpkg-query -W podman crun fuse-overlayfs slirp4netns netavark aardvark-dns
    ;;
verify)
    uid=$(cat "$base/uid")
    as_user systemctl --user is-active --quiet podman.socket
    test "$(pod exec compat-server cat /data/marker)" = "$nonce"
    test "$(pod exec compat-server cat /bind/marker)" = "$nonce"
    before=$(awk '{print $1, $22}' "$base/process")
    after=$(pod exec compat-server cat /proc/1/stat | awk '{print $1, $22}')
    test "$before" = "$after"
    pod exec compat-server sh -ec '
        test "$(cat /sys/fs/cgroup/memory.max)" = 67108864
        test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
        test "$(cat /sys/fs/cgroup/pids.max)" = 64'
    test "$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:18087)" = "$nonce"
    test "$(pod run --rm --network compat-net "$image" wget -qO- http://compat-server:8080)" = "$nonce"
    test "$(pod run --rm localhost/flexvm-rootless-built cat /built)" = rootless-service-build
    printf 'ROOTLESS_PODMAN_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
