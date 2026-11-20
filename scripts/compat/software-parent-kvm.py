#!/usr/bin/env python3
"""Boot unchanged Firecracker twice through the public parent KVM launch path."""
import argparse
import json
from pathlib import Path
import runpy
import tempfile

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / "software-boot.py"))
image = runpy.run_path(str(ROOT / "software-kvm.py"))["image"]
DEVICES = ("/dev/kvm", "/dev/vhost-net", "/dev/vhost-vsock")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bin", "kernel", "firecracker", "qemu", "bundle", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--engine", choices=("auto", "tcg", "kvm"), default="tcg")
    args = parser.parse_args()
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
    image(archive, "amd64", {
        "kvm-workload": (app.read_bytes(), 0o755),
        "firecracker": (firecracker.read_bytes(), 0o755),
        "firecracker-kernel": (kernel.read_bytes(), 0o600),
        "firecracker-initrd": (HELPERS["initramfs"](init.read_bytes(), files={"firecracker-network": b""}), 0o600),
        "firecracker-network": (b"", 0o600),
        "firecracker.json": (json.dumps(config).encode(), 0o600),
        "etc/passwd": (b"root:x:0:0:root:/root:/bin/sh\n", 0o644),
        "etc/group": (b"root:x:0:\n", 0o644),
    })
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
        HELPERS["run"]([
            "unshare", "--mount", "--propagation", "private", "sh", "-ec", setup, "sh", mask, args.engine,
            "strace", "-f", "-e", "trace=file", "-o", trace,
            binary, "software", "--kernel", kernel, "--qemu", qemu, "--state", state, "--verbose",
            "--parent-kvm-bundle", bundle, "--parent-kvm-engine", args.engine, "--parent-kvm-mem", "128",
            "--mem", "512", archive,
        ], 180, log)
    transcript = log.read_text(errors="replace")
    for marker in ("FLEXVM_SOFTWARE_INNER_CPU 0", "FLEXVM_SOFTWARE_INNER_CPU 1", "FLEXVM_SOFTWARE_INNER_COMPLETE",
                   "PASS Firecracker network echo"):
        if transcript.splitlines().count(marker) != 2:
            raise RuntimeError(f"expected two occurrences of {marker}; see {log}")
    if "PASS parent KVM device reuse" not in transcript:
        raise RuntimeError(f"parent device reuse failed; see {log}")
    lines = trace.read_text(errors="replace").splitlines()
    devices = {device for device in DEVICES if any(f'"{device}"' in line for line in lines)}
    expected = {"/dev/kvm"} if args.engine in ("auto", "kvm") else set()
    if devices != expected:
        raise RuntimeError(f"unexpected host virtualization device accesses: {sorted(devices)}")
    if args.engine in ("auto", "kvm"):
        workers = {line.split()[0] for line in lines if '/provider/native-worker"' in line and "execve(" in line}
        users = {line.split()[0] for line in lines if '"/dev/kvm"' in line}
        # The startup probe uses the original bundle path, then the broker
        # uses its private bundle reference for actual child execution.
        probes = {line.split()[0] for line in lines if f'execve("{bundle / "native-worker"}",' in line}
        workers -= probes
        expected_workers = len(workers) >= 2 if args.engine == "kvm" else not workers
        if len(probes) != 1 or not expected_workers or users != workers | probes:
            raise RuntimeError("only the expected native worker processes may access host KVM")
    report = {"status": "passed", "engine": "tcg" if args.engine == "auto" else args.engine, "selection": args.engine,
              "nested_vcpus": 2, "nested_starts": 2, "firecracker_sha256": HELPERS["digest"](firecracker),
              "host_virtualization_devices": sorted(devices)}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
