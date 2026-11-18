#!/usr/bin/env python3
"""Boot unchanged Firecracker twice through the public parent KVM launch path."""
import argparse
import json
from pathlib import Path
import re
import runpy
import tempfile
import time

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / "software-boot.py"))
image = runpy.run_path(str(ROOT / "software-kvm.py"))["image"]
DEVICES = ("/dev/kvm", "/dev/vhost-net", "/dev/vhost-vsock")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bin", "kernel", "firecracker", "qemu", "bundle", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--engine", choices=("auto", "tcg", "kvm"), default="tcg")
    lifecycle = parser.add_mutually_exclusive_group()
    lifecycle.add_argument("--pause", action="store_true", help="pause and resume the first nested VM through the public command")
    lifecycle.add_argument("--suspend", action="store_true", help="stop and restore the first nested VM through the public command")
    lifecycle.add_argument("--suspend-idle", action="store_true", help="stop and restore before starting the first nested VM")
    lifecycle.add_argument("--suspend-initial", action="store_true", help="stop and restore a nested VM before its first run")
    args = parser.parse_args()
    suspend = args.suspend or args.suspend_idle or args.suspend_initial
    if suspend and args.engine == "auto":
        parser.error("checkpoint testing requires an explicit parent provider")
    binary, kernel, firecracker, qemu, bundle = (
        path.resolve(strict=True) for path in (args.bin, args.kernel, args.firecracker, args.qemu, args.bundle)
    )
    output = args.output.resolve()
    output.mkdir()
    app, init = output / "workload", output / "inner-init"
    cc = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static"]
    HELPERS["run"]([*cc, "-DFLEXVM_PARENT_KVM_APP", ROOT / "parent-kvm/init.c", "-o", app], 30, output / "app-build.log")
    HELPERS["run"]([*cc, ROOT / "nested-init.c", "-o", init], 30, output / "init-build.log")
    config = {
        "boot-source": {
            "kernel_image_path": "/firecracker-kernel",
            "initrd_path": "/firecracker-initrd",
            "boot_args": "console=ttyS0 quiet panic=1 rdinit=/init reboot=k",
        },
        "machine-config": {"vcpu_count": 2, "mem_size_mib": 128},
        "drives": [],
        "network-interfaces": [{"iface_id": "eth0", "host_dev_name": "flexvmtap", "guest_mac": "02:00:00:00:00:02"}],
    }
    archive = output / "image.tar"
    inner_files = {"firecracker-network": b""}
    if args.suspend:
        inner_files["firecracker-checkpoint"] = b""
    files = {
        "kvm-workload": (app.read_bytes(), 0o755),
        "firecracker": (firecracker.read_bytes(), 0o755),
        "firecracker-kernel": (kernel.read_bytes(), 0o600),
        "firecracker-initrd": (HELPERS["initramfs"](init.read_bytes(), files=inner_files), 0o600),
        "firecracker-network": (b"", 0o600),
        "firecracker.json": (json.dumps(config).encode(), 0o600),
        "etc/passwd": (b"root:x:0:0:root:/root:/bin/sh\n", 0o644),
        "etc/group": (b"root:x:0:\n", 0o644),
    }
    if args.suspend_idle:
        files["firecracker-idle-checkpoint"] = (b"", 0o600)
    if args.suspend_initial:
        files["firecracker-initial-checkpoint"] = (b"", 0o600)
    image(archive, "amd64", files)
    setup = """
        for device in /dev/kvm /dev/vhost-net /dev/vhost-vsock; do
            if [ "$device" = /dev/kvm ] && [ "$2" = kvm ]; then continue; fi
            if [ -e "$device" ]; then mount --bind "$1" "$device"; fi
        done
        shift 2
        exec "$@"
    """
    trace, log = output / "files.strace", output / "guest.log"
    with tempfile.TemporaryDirectory(prefix="flexvm-software-parent-", dir="/var/lib") as state:
        mask = Path(state) / "mask"
        mask.touch(mode=0o600)
        prefix = ["unshare", "--mount", "--propagation", "private", "sh", "-ec", setup, "sh", mask, args.engine,
                  "strace", "-f", "-e", "trace=file", "-o"]
        command = [
            *prefix, trace, binary, "software", "--kernel", kernel, "--qemu", qemu, "--state", state, "--verbose",
            "--parent-kvm-bundle", bundle, "--parent-kvm-engine", args.engine, "--parent-kvm-mem", "128", "--mem", "512",
        ]
        during = None
        if args.pause:
            name = "parent-kvm-pause"
            command.extend(["--name", name])
            during = lambda proc, deadline: pause_nested(proc, deadline, binary, state, name, output, log)
        if suspend:
            suspend_nested(command, prefix, archive, binary, state, output, log,
                           idle=args.suspend_idle, initial=args.suspend_initial)
        else:
            HELPERS["run"]([*command, archive], 180, log, during=during)
    transcript = log.read_text(errors="replace")
    for marker in ("FLEXVM_SOFTWARE_INNER_CPU 0", "FLEXVM_SOFTWARE_INNER_CPU 1", "FLEXVM_SOFTWARE_INNER_COMPLETE",
                   "PASS Firecracker network echo"):
        if transcript.splitlines().count(marker) != 2:
            raise RuntimeError(f"expected two occurrences of {marker}; see {log}")
    if "PASS parent KVM device reuse" not in transcript:
        raise RuntimeError(f"parent device reuse failed; see {log}")
    if args.suspend_initial and "PASS x86 parent KVM staged worker state" not in transcript:
        raise RuntimeError(f"the x86 hierarchy did not restore staged worker state; see {log}")
    if args.suspend:
        before = re.findall(r"FLEXVM_SOFTWARE_INNER_CANARY ([0-9a-f]{16})", transcript)
        after = re.findall(r"FLEXVM_SOFTWARE_INNER_RESTORED ([0-9a-f]{16})", transcript)
        if len(before) != 2 or before != after:
            raise RuntimeError(f"the x86 hierarchy lost its memory canary; see {log}")
    traces = [trace, output / "target.strace"] if suspend else [trace]
    lines = [line for path in traces for line in path.read_text(errors="replace").splitlines()]
    devices = {device for device in DEVICES if any(f'"{device}"' in line for line in lines)}
    expected = {"/dev/kvm"} if args.engine in ("auto", "kvm") else set()
    if devices != expected:
        raise RuntimeError(f"unexpected host virtualization device accesses: {sorted(devices)}")
    if args.engine in ("auto", "kvm"):
        workers = {line.split()[0] for line in lines if '/provider/native-worker"' in line and "execve(" in line}
        users = {line.split()[0] for line in lines if '"/dev/kvm"' in line}
        # The startup probe uses the original bundle path, then the broker
        # uses its private bundle reference for actual child execution.
        probes = {line.split()[0] for line in lines
                  if 'native-worker",' in line and '"--supported-cpuid"' in line and "execve(" in line and '/provider/native-worker"' not in line}
        workers -= probes
        expected_workers = len(workers) >= 2 if args.engine == "kvm" else not workers
        if len(probes) != 1 or not expected_workers or users != workers | probes:
            raise RuntimeError("only the expected native worker processes may access host KVM")
    report = {"status": "passed", "engine": "tcg" if args.engine == "auto" else args.engine, "selection": args.engine,
              "nested_vcpus": 2, "nested_starts": 2, "firecracker_sha256": HELPERS["digest"](firecracker),
              "host_virtualization_devices": sorted(devices), "paused_hierarchy": args.pause, "restored_hierarchy": suspend,
              "restored_idle": args.suspend_idle, "restored_initial": args.suspend_initial}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def wait_nested_window(proc, deadline, log, marker):
    while not re.search(marker, log.read_text(errors="replace")):
        if proc.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError("the nested x86 guest did not reach its checkpoint window")
        time.sleep(.01)


def suspend_nested(command, prefix, archive, binary, state, output, log, *, idle, initial):
    name = "parent-kvm-suspend"
    source, target = output / "source.log", output / "target.log"

    marker = next((name for selected, name in ((idle, "FLEXVM_X86_PARENT_IDLE"), (initial, "FLEXVM_X86_PARENT_INITIAL"))
                   if selected), r"FLEXVM_SOFTWARE_INNER_CANARY [0-9a-f]{16}")

    def stop(proc, deadline):
        wait_nested_window(proc, deadline, source, marker)
        HELPERS["run"]([binary, "stop", "--state", state, name], 90, output / "stop.log")

    try:
        HELPERS["run"]([*command, "--name", name, archive], 180, source, during=stop)
        checkpoint = Path(state) / "suspended" / name
        manifest = json.loads((checkpoint / "manifest.json").read_text())
        if not (checkpoint / "RETIRED").is_file() or manifest["parent"]["child_memory_mib"] != 128:
            raise RuntimeError("the x86 owner did not retire a complete hierarchy")
        if idle or initial:
            expected = b"FLEXVM x86 worker has not run\n" if initial else b"FLEXVM x86 no nested worker\n"
            if (checkpoint / "parent-worker").read_bytes() != expected:
                raise RuntimeError("the x86 checkpoint has an unexpected nested worker marker")
        HELPERS["run"]([*prefix, output / "target.strace", binary, "start", "-a", "--state", state, name], 150, target)
    finally:
        log.write_bytes(b"".join(part.read_bytes() for part in (source, target) if part.exists()))


def pause_nested(proc, deadline, binary, state, name, output, log):
    marker = "FLEXVM_SOFTWARE_INNER_TICK 0"
    wait_nested_window(proc, deadline, log, marker)
    HELPERS["run"]([binary, "pause", "--state", state, name], 15, output / "pause.log")
    paused = log.read_text(errors="replace").split(marker, 1)[-1]
    if "software: parent KVM vCPUs quiesced" not in paused:
        raise RuntimeError("the x86 parent did not fence its nested run lanes")
    ticks = log.read_text(errors="replace").count("FLEXVM_SOFTWARE_INNER_TICK")
    time.sleep(5)
    if proc.poll() is not None or log.read_text(errors="replace").count("FLEXVM_SOFTWARE_INNER_TICK") != ticks:
        raise RuntimeError("the nested x86 guest advanced while the hierarchy was paused")
    HELPERS["run"]([binary, "unpause", "--state", state, name], 15, output / "unpause.log")


if __name__ == "__main__":
    main()
