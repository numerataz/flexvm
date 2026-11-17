#!/bin/sh
# Ordinary logind/user-manager setup, retaining live delegated user services.
set -eux
step=$1 nonce=$2 phase=$3
base=/var/lib/flexvm-user-session-$nonce
user=fu$(printf %.12s "$nonce")
as_user() {
    runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" "$@"
}
bus_id() {
    as_user dbus-send --session --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.GetId |
        sed -n 's/^ *string "\([0-9a-f]*\)"$/\1/p'
}
case $step in
prepare)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends dbus dbus-user-session libpam-systemd passwd uidmap python3
    systemctl start dbus.service systemd-logind.service
    mkdir "$base"
    useradd -m -s /bin/sh "$user"
    uid=$(id -u "$user")
    printf '%s\n' "$uid" > "$base/uid"
    grep -q "^$user:" /etc/subuid
    grep -q "^$user:" /etc/subgid
    loginctl enable-linger "$user"
    systemctl start "user@$uid.service"
    install -d -m 755 -o "$user" -g "$user" "/home/$user/.config/systemd/user"
    cat > "/home/$user/session-probe.py" <<'PY'
import json, os, pathlib, secrets, time
root = pathlib.Path(os.environ['XDG_RUNTIME_DIR'])
cookie, counter = secrets.token_hex(16), 0
while True:
    counter += 1
    value = dict(cookie=cookie, counter=counter, pid=os.getpid(),
                 start=pathlib.Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19])
    (root / 'session-probe.new').write_text(json.dumps(value))
    os.replace(root / 'session-probe.new', root / 'session-probe.json')
    time.sleep(.05)
PY
    cat > "/home/$user/.config/systemd/user/flexvm-session-probe.service" <<EOF
[Service]
ExecStart=/usr/bin/python3 /home/$user/session-probe.py
MemoryMax=67108864
TasksMax=16
CPUQuota=50%
EOF
    chown -R "$user:$user" "/home/$user"
    as_user systemctl --user daemon-reload
    as_user systemctl --user start flexvm-session-probe.service
    for attempt in $(seq 1 100); do
        if [ -s "/run/user/$uid/session-probe.json" ]; then break; fi
        sleep .1
    done
    cp "/run/user/$uid/session-probe.json" "$base/initial"
    bus_id > "$base/bus"
    test "$(wc -c < "$base/bus")" = 33
    systemctl show --property=MainPID --value "user@$uid.service" > "$base/manager"
    dpkg-query -W dbus dbus-user-session libpam-systemd uidmap
    ;;
verify)
    uid=$(cat "$base/uid")
    test "$(systemctl show --property=MainPID --value "user@$uid.service")" = "$(cat "$base/manager")"
    systemctl is-active --quiet "user@$uid.service" systemd-logind.service
    as_user systemctl --user is-active --quiet flexvm-session-probe.service
    test "$(bus_id)" = "$(cat "$base/bus")"
    group=$(as_user systemctl --user show --property=ControlGroup --value flexvm-session-probe.service)
    test "$(cat "/sys/fs/cgroup$group/memory.max")" = 67108864
    test "$(cat "/sys/fs/cgroup$group/pids.max")" = 16
    test "$(cat "/sys/fs/cgroup$group/cpu.max")" = '50000 100000'
    python3 - "$base/initial" "/run/user/$uid/session-probe.json" <<'PY'
import json, pathlib, sys, time
before = json.loads(pathlib.Path(sys.argv[1]).read_text())
path = pathlib.Path(sys.argv[2])
now = json.loads(path.read_text())
assert all(now[key] == before[key] for key in ('pid', 'start', 'cookie')), (before, now)
time.sleep(.2)
after = json.loads(path.read_text())
assert after['counter'] > now['counter'], (now, after)
print(after)
PY
    printf 'USER_SESSION_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
