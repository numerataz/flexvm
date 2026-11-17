#!/bin/sh
# A real init and service manager, with identity preserved across software state restoration.
set -eux
step=$1 nonce=$2 phase=$3
base=/run/flexvm-distro-$nonce
identity() {
    python3 -c 'import json,os,pathlib; p=pathlib.Path; print(json.dumps(dict(executable=os.readlink("/proc/1/exe"), start=p("/proc/1/stat").read_text().rsplit(")",1)[1].split()[19], machine=p("/etc/machine-id").read_text().strip(), hostname=p("/proc/sys/kernel/hostname").read_text().strip()), sort_keys=True))'
}
case $step in
prepare)
    test "$(cat /proc/1/comm)" = systemd
    case $(readlink /proc/1/exe) in */systemd) ;; *) exit 1 ;; esac
    test "$(hostname)" = workload-test
    test "$(cat /etc/hostname)" = workload-test
    mkdir "$base"
    identity > "$base/identity"
    systemctl is-system-running --wait
    systemctl is-active --quiet flexvm-runtime.service
    test "$(systemctl show --property=Delegate --value flexvm-runtime.service)" = yes
    ;;
verify)
    test "$(cat /proc/self/oom_score_adj)" = 0
    test "$(identity)" = "$(cat "$base/identity")"
    systemctl is-active --quiet flexvm-state-probe.service flexvm-runtime.service
    test "$(systemctl show --property=Delegate --value flexvm-runtime.service)" = yes
    cat /proc/self/cgroup
    identity
    printf 'SYSTEMD_PHASE_OK %s\n' "$phase"
    ;;
*) exit 2 ;;
esac
