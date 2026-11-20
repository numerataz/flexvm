#!/bin/sh
# Guest-only namespace/bubblewrap and gVisor systrap acceptance.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-sandboxes-$nonce
user=sb$(printf %.12s "$nonce")
image=public.ecr.aws/docker/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
pod() { podman --cgroup-manager=cgroupfs --runtime /usr/local/bin/flexvm-runsc "$@"; }
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates curl bzip2 python3 bubblewrap util-linux podman crun fuse-overlayfs iptables netavark aardvark-dns
    mkdir -p "$base" /etc/containers
    chmod 755 "$base"
    uname -r
    dpkg-query -W bubblewrap python3 podman crun fuse-overlayfs
    case $(uname -m) in
        x86_64) archive=gvisor-x86_64.tar.bz2; digest=0846228061b05eb936a96ed2ea205cbd8ddf6936c946f8a390b699cff3b5c138 ;;
        aarch64) archive=gvisor-aarch64.tar.bz2; digest=795f87ab171b7a228d8b0e7e2d422c41c29dc7e37792f21099589dc3527ab1f0 ;;
        *) exit 2 ;;
    esac
    curl --fail --location --retry 2 --output "$base/gvisor.tar.bz2" "https://github.com/google/gvisor/releases/download/release-20261109.0/$archive"
    printf '%s  %s\n' "$digest" "$base/gvisor.tar.bz2" | sha256sum --check --strict
    tar -xjf "$base/gvisor.tar.bz2" -C /usr/local/bin
    /usr/local/bin/runsc --version
    cat > /usr/local/bin/flexvm-runsc <<'WRAPPER'
#!/bin/sh
exec /usr/local/bin/runsc --platform=systrap "$@"
WRAPPER
    chmod 755 /usr/local/bin/flexvm-runsc
    # Force the software backend throughout this VM; these are guest mounts.
    for device in /dev/kvm /dev/vhost-vsock; do
        if [ -e "$device" ]; then mount --bind /dev/null "$device"; fi
    done
    cat > /etc/containers/storage.conf <<'STORAGE'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
STORAGE
    cat > /etc/containers/containers.conf <<'CONTAINERS'
[network]
network_backend = "netavark"
[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"
CONTAINERS
    useradd -m -s /bin/sh "$user"
    uid=$(id -u "$user")
    mkdir "$base/bwrap-share"
    chown "$user:$user" "$base/bwrap-share"
    echo "$nonce" > "$base/guest-marker"
    cat > "$base/bwrap-probe.py" <<'PROBE'
import ctypes, errno, json, os, secrets, socket, sys, time
share, hidden, syscall_number, outer, ipc_id = sys.argv[1:]
assert os.getuid() == 0
assert socket.gethostname() == 'flexvm-bwrap'
assert not os.path.exists(hidden), 'guest filesystem leaked into sandbox'
assert os.statvfs('/usr').f_flag & os.ST_RDONLY
assert {name for _, name in socket.if_nameindex()} <= {'lo'}
assert os.stat('/proc/self/ns/user').st_ino != int(outer)
libc = ctypes.CDLL(None, use_errno=True)
assert libc.syscall(int(syscall_number)) == -1 and ctypes.get_errno() == errno.EPERM
assert libc.shmctl(int(ipc_id), 2, ctypes.create_string_buffer(512)) == -1 and ctypes.get_errno() == errno.EINVAL
assert os.getpid() <= 2
cookie = secrets.token_hex(16)
start = open('/proc/self/stat').read().rsplit(')', 1)[1].split()[19]
counter = 0
while True:
    counter += 1
    with open(share + '/current.tmp', 'w') as output:
        json.dump(dict(cookie=cookie, pid=os.getpid(), start=start, counter=counter), output)
    os.replace(share + '/current.tmp', share + '/current.json')
    time.sleep(.1)
PROBE
    python3 - "$base/seccomp.bpf" <<'FILTER'
import platform, struct, sys
number = {'x86_64': 110, 'aarch64': 173}[platform.machine()]
with open(sys.argv[1], 'wb') as output:
    for instruction in [(0x20, 0, 0, 0), (0x15, 0, 1, number), (0x06, 0, 0, 0x50001), (0x06, 0, 0, 0x7fff0000)]:
        output.write(struct.pack('HBBI', *instruction))
FILTER
    number=110
    if [ "$(uname -m)" = aarch64 ]; then number=173; fi
    outer=$(stat -Lc %i /proc/self/ns/user)
    ipc=$(ipcmk -M 4096 | awk '{print $NF}')
    # A separate util-linux case verifies PID/mount/IPC/UTS/user namespaces.
    runuser -u "$user" -- unshare --user --map-root-user --mount --pid --fork --mount-proc --ipc --uts sh -ec 'test "$$" = 1; test "$(id -u)" = 0; test "$(cat /proc/1/comm)" = sh'
    runuser -u "$user" -- sh -ec 'base=$1; number=$2; outer=$3; ipc=$4
        exec bwrap --unshare-all --uid 0 --gid 0 --hostname flexvm-bwrap --new-session --die-with-parent \
          --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind-try /lib64 /lib64 \
          --proc /proc --dev /dev --tmpfs /tmp --dir /work --bind "$base/bwrap-share" /work \
          --ro-bind "$base/bwrap-probe.py" /probe.py --seccomp 3 \
          /usr/bin/python3 /probe.py /work "$base/guest-marker" "$number" "$outer" "$ipc" 3<"$base/seccomp.bpf"' \
          sh "$base" "$number" "$outer" "$ipc" > "$base/bwrap.log" 2>&1 &
    echo $! > "$base/bwrap-owner"
    ready=false
    for attempt in $(seq 1 100); do
        if [ -f "$base/bwrap-share/current.json" ]; then ready=true; break; fi
        sleep .1
    done
    if ! "$ready"; then cat "$base/bwrap.log"; exit 3; fi
    cp "$base/bwrap-share/current.json" "$base/bwrap-before.json"
    pod pull "$image"
    pod image inspect --format '{{.Id}} {{.Digest}} {{.Architecture}}' "$image"
    pod create --name chroot-seed "$image" true
    pod export chroot-seed > "$base/chroot.tar"
    pod rm chroot-seed
    mkdir "$base/chroot"
    tar -xf "$base/chroot.tar" -C "$base/chroot"
    printf '%s' "$nonce" > "$base/chroot/marker"
    chroot "$base/chroot" /bin/sh -ec 'test ! -e "$1"; test -x /bin/busybox; test "$(cat /marker)" = "$2"' sh "$base/guest-marker" "$nonce"
    pod network create sandbox-net
    pod run -d --name sandbox-server --network sandbox-net --cgroup-parent=/sandbox-parent --memory=512m --cpus=1 --pids-limit=128 -p 18083:8080 "$image" sh -ec '
        test ! -e "$1"
        mkdir /www
        cookie=$(od -An -tx1 -N16 /dev/urandom | tr -d " \n")
        echo "$cookie" >/www/cookie
        httpd -f -p 8080 -h /www &
        i=0; while :; do i=$((i+1)); echo "$i" >/www/counter.tmp; mv /www/counter.tmp /www/counter; sleep .1; done
    ' sh "$base/guest-marker"
    curl --fail --silent --show-error --retry 20 --retry-connrefused --retry-delay 1 http://127.0.0.1:18083/cookie > "$base/gvisor-cookie"
    pod exec sandbox-server cat /proc/1/stat > "$base/gvisor-process"
    pod run --rm --network sandbox-net --cgroup-parent=/sandbox-parent "$image" wget -qO- http://sandbox-server:8080/cookie | cmp - "$base/gvisor-cookie"
    pod run --rm --network sandbox-net --cgroup-parent=/sandbox-parent "$image" wget -qO /dev/null https://github.com/robots.txt
    ;;
verify)
    chroot "$base/chroot" /bin/sh -ec 'test ! -e "$1"; test "$(cat /marker)" = "$2"' sh "$base/guest-marker" "$nonce"
    for device in /dev/kvm /dev/vhost-vsock; do
        if [ -e "$device" ]; then test "$(stat -c %t:%T "$device")" = 1:3; fi
    done
    python3 - "$base/bwrap-before.json" "$base/bwrap-share/current.json" <<'VERIFY'
import json, sys, time
before = json.load(open(sys.argv[1]))
initial = json.load(open(sys.argv[2]))
assert all(initial[key] == before[key] for key in ('cookie', 'pid', 'start'))
deadline = time.monotonic() + 15
while True:
    after = json.load(open(sys.argv[2]))
    assert all(after[key] == before[key] for key in ('cookie', 'pid', 'start'))
    if after['counter'] >= initial['counter'] + 2 and after['counter'] > before['counter']:
        break
    assert time.monotonic() < deadline, 'sandbox stopped making fresh progress'
    time.sleep(.05)
print('bubblewrap:', json.dumps(dict(before=before, initial=initial, after=after), sort_keys=True))
VERIFY
    before=$(awk '{print $1, $22}' "$base/gvisor-process")
    after=$(pod exec sandbox-server cat /proc/1/stat | awk '{print $1, $22}')
    test "$before" = "$after"
    curl --fail --silent --show-error http://127.0.0.1:18083/cookie | cmp - "$base/gvisor-cookie"
    python3 - <<'HTTPPROGRESS'
import time, urllib.request

def value():
    with urllib.request.urlopen('http://127.0.0.1:18083/counter', timeout=3) as response:
        return int(response.read())
initial = value()
deadline = time.monotonic() + 15
while True:
    after = value()
    if after >= initial + 2:
        break
    assert time.monotonic() < deadline, 'gVisor stopped making fresh progress'
    time.sleep(.05)
print('gVisor fresh counter:', initial, '->', after)
HTTPPROGRESS
    echo "gVisor PID/starttime: $before"
    echo "chroot filesystem, bubblewrap namespace/seccomp/process state and gVisor systrap filesystem/process/network state passed after $phase"
    ;;
*) exit 2 ;;
esac
