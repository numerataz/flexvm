#!/bin/sh
# Stock Docker rootless installer and a normal delegated systemd user service.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-rootless-docker-$nonce
user=fd$(printf %.12s "$nonce")
image=public.ecr.aws/docker/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
as_user() {
    runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" "$@"
}
dock() { as_user env DOCKER_HOST="unix:///run/user/$uid/docker.sock" docker "$@"; }
build() {
    epoch=1
    if [ -f "$base/build-counter" ]; then epoch=$(($(cat "$base/build-counter")+1)); fi
    dock buildx build --load --build-arg "RUN_EPOCH=$epoch" --secret "id=token,src=$base/secret" \
        --tag flexvm-rootless-built "$base/context"
    test "$(dock run --rm flexvm-rootless-built cat /built)" = "$epoch"
    dock run --rm flexvm-rootless-built sh -ec 'test ! -e /run/secrets/token; test "$(cat /secret-check)" = ok'
    printf '%s\n' "$epoch" > "$base/build-counter"
}
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates curl iptables uidmap slirp4netns fuse-overlayfs \
        dbus dbus-user-session libpam-systemd passwd
    systemctl start dbus.service systemd-logind.service
    mkdir -p "$base/context" /usr/local/lib/docker/cli-plugins
    chmod 755 "$base"
    case $(uname -m) in
        x86_64)
            arch=amd64
            engine=40c16bcf324f354b382d07e845e6a79e3493fc0c09b252dff9e1a46125589bff
            extras=fdf844dfea6b4b23358c1587bec497a285aebf0a1105cede4cfeb001ffcc67ff
            buildx=696bc104bac3bb708eff1af3f8bbc09fda0fd88f5757c1f9b404a35117889224
            ;;
        aarch64)
            arch=arm64
            engine=db69fed523677c5a24bbc6ef2e85db07205a6af2fe8838c4db652bfff8227cfa
            extras=45c939d8ad88d4762001a767e0fb7abf1018a4d8666c276c973c1d9c0f53e3d1
            buildx=4e850583cc68ffd8d739ddb8a782b83f2ef9d3bf437ae7c44da4fbfde2613a8e
            ;;
        *) exit 2 ;;
    esac
    curl --fail --location --retry 2 -o "$base/docker.tgz" "https://download.docker.com/linux/static/stable/$(uname -m)/docker-28.3.3.tgz"
    curl --fail --location --retry 2 -o "$base/extras.tgz" "https://download.docker.com/linux/static/stable/$(uname -m)/docker-rootless-extras-28.3.3.tgz"
    curl --fail --location --retry 2 -o "$base/buildx" "https://github.com/docker/buildx/releases/download/v0.28.0/buildx-v0.28.0.linux-$arch"
    printf '%s  %s\n%s  %s\n%s  %s\n' "$engine" "$base/docker.tgz" "$extras" "$base/extras.tgz" "$buildx" "$base/buildx" | sha256sum --check --strict
    tar -xzf "$base/docker.tgz" -C /usr/local/bin --strip-components=1
    tar -xzf "$base/extras.tgz" -C /usr/local/bin --strip-components=1
    install -m 755 "$base/buildx" /usr/local/lib/docker/cli-plugins/docker-buildx
    rm "$base/docker.tgz" "$base/extras.tgz" "$base/buildx"
    useradd -m -s /bin/sh "$user"
    uid=$(id -u "$user")
    printf '%s\n' "$uid" > "$base/uid"
    grep -q "^$user:" /etc/subuid
    grep -q "^$user:" /etc/subgid
    loginctl enable-linger "$user"
    systemctl start "user@$uid.service"
    install -d -m 700 -o "$user" -g "$user" "/home/$user/.config" "/home/$user/.config/docker"
    printf '%s\n' '{"storage-driver":"fuse-overlayfs"}' > "/home/$user/.config/docker/daemon.json"
    chown "$user:$user" "/home/$user/.config/docker/daemon.json"
    as_user dockerd-rootless-setuptool.sh install
    dock version
    dock info
    test "$(dock info --format '{{.Driver}}')" = fuse-overlayfs
    test "$(dock info --format '{{.CgroupDriver}}')" = systemd
    test "$(dock info --format '{{.CgroupVersion}}')" = 2
    dock info --format '{{json .SecurityOptions}}' | grep 'name=rootless'
    as_user systemctl --user show docker.service --property=Delegate --property=MainPID
    test "$(as_user systemctl --user show docker.service --property=Delegate --value)" = yes
    dock pull "$image"
    dock image inspect "$image"
    dock network create compat-net
    dock volume create compat-data
    mkdir "$base/bind"
    chown "$user:$user" "$base/bind"
    dock run --rm -v "$base/bind:/bind" "$image" sh -ec 'echo "$1" >/bind/marker' sh "$nonce"
    dock run --rm -v compat-data:/data "$image" sh -ec 'echo "$1" >/data/marker' sh "$nonce"
    dock run --rm --network compat-net --memory=64m --cpus=.5 --pids-limit=64 "$image" sh -ec '
        test "$(cat /sys/fs/cgroup/memory.max)" = 67108864
        test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
        test "$(cat /sys/fs/cgroup/pids.max)" = 64
        wget -qO /dev/null http://example.com'
    dock run -d --name compat-server --network compat-net --memory=64m --cpus=.5 --pids-limit=64 -p 18085:8080 -v compat-data:/data -v "$base/bind:/bind:ro" "$image" sh -ec '
        mkdir /www; cp /data/marker /www/index.html; exec httpd -f -p 8080 -h /www'
    dock exec compat-server cat /proc/1/stat > "$base/process"
    printf '%s\n' "$nonce" > "$base/secret"
    cat > "$base/context/Dockerfile" <<EOF
FROM $image
ARG RUN_EPOCH
RUN --mount=type=cache,target=/cache --mount=type=secret,id=token \\
    set -eu; test -s /run/secrets/token; echo ok >/secret-check; \\
    previous=0; if [ -f /cache/counter ]; then previous=\$(cat /cache/counter); fi; \\
    next=\$((previous+1)); test "\$next" = "\$RUN_EPOCH"; echo "\$next" >/cache/counter; cp /cache/counter /built
EOF
    chown -R "$user:$user" "$base/context"
    chmod 644 "$base/secret"
    build
    ;;
verify)
    uid=$(cat "$base/uid")
    as_user systemctl --user is-active --quiet docker.service
    test "$(dock exec compat-server cat /data/marker)" = "$nonce"
    test "$(dock exec compat-server cat /bind/marker)" = "$nonce"
    before=$(awk '{print $1, $22}' "$base/process")
    after=$(dock exec compat-server cat /proc/1/stat | awk '{print $1, $22}')
    test "$before" = "$after"
    dock exec compat-server sh -ec '
        test "$(cat /sys/fs/cgroup/memory.max)" = 67108864
        test "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000"
        test "$(cat /sys/fs/cgroup/pids.max)" = 64'
    test "$(curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:18085)" = "$nonce"
    test "$(dock run --rm --network compat-net "$image" wget -qO- http://compat-server:8080)" = "$nonce"
    build
    printf 'ROOTLESS_DOCKER_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
