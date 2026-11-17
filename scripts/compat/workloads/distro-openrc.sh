#!/bin/sh
# Actual OpenRC PID 1 and supervised services through software state restoration.
set -eux
step=$1 nonce=$2 phase=$3
base=/run/flexvm-distro-$nonce
identity() {
    python3 -c 'import json,os,pathlib; p=pathlib.Path; print(json.dumps(dict(executable=os.readlink("/proc/1/exe"), start=p("/proc/1/stat").read_text().rsplit(")",1)[1].split()[19], machine=p("/etc/machine-id").read_text().strip(), hostname=p("/proc/sys/kernel/hostname").read_text().strip()), sort_keys=True))'
}
bus_id() {
    dbus-send --system --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.GetId |
        sed -n 's/^ *string "\([0-9a-f]*\)"$/\1/p'
}
case $step in
prepare)
    test "$(cat /proc/1/comm)" = openrc-init
    test "$(readlink /proc/1/exe)" = /sbin/openrc-init
    test "$(hostname)" = workload-test
    test "$(cat /etc/hostname)" = workload-test
    mkdir "$base"
    identity > "$base/identity"
    rc-service dbus start
    rc-service udev start
    udevadm control --reload-rules
    udevadm trigger --action=add --subsystem-match=net
    udevadm settle --timeout=15
    ip link show dev eth0
    bus_id > "$base/bus"
    test "$(wc -c < "$base/bus")" = 33
    ;;
verify)
    test "$(identity)" = "$(cat "$base/identity")"
    rc-service flexvm-runtime status
    rc-service flexvm-state-probe status
    rc-service udev status
    test "$(bus_id)" = "$(cat "$base/bus")"
    test "$(cat /sys/fs/cgroup/openrc.flexvm-state-probe/memory.max)" = 67108864
    test "$(cat /sys/fs/cgroup/openrc.flexvm-state-probe/pids.max)" = 16
    cat /proc/self/cgroup
    identity
    printf 'OPENRC_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
