#!/usr/bin/env python3
"""Run released ARM Firecracker through FlexVM's owned KVM device."""
import argparse
import json
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / "software-boot.py"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "bundle", "firecracker", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--vcpus", type=int, choices=(1, 2), default=2)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir()
    cc = [args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static"]
    outer, inner = output / "outer-init", output / "inner-init"
    HELPERS["run"]([*cc, ROOT / "parent-kvm/arm-firecracker-init.c", "-o", outer], 30, output / "outer-build.log")
    HELPERS["run"]([*cc, f"-DFLEXVM_ARM_TEST_CPUS={args.vcpus}", ROOT / "parent-kvm/arm-block-init.c", "-o", inner],
                   30, output / "inner-build.log")
    kernel = args.kernel.resolve(strict=True)
    config = {
        "boot-source": {"kernel_image_path": "/inner-kernel", "initrd_path": "/inner.cpio",
                        "boot_args": "console=ttyS0 quiet panic=1 rdinit=/init"},
        "machine-config": {"vcpu_count": args.vcpus, "mem_size_mib": 128},
        "drives": [{"drive_id": "blk", "path_on_host": "/tmp/drive", "is_root_device": False, "is_read_only": False}],
    }
    cpio = output / "initramfs"
    cpio.write_bytes(HELPERS["initramfs"](outer.read_bytes(), files={
        "flexvm-pvkvm.ko": (args.bundle / "flexvm-pvkvm.ko").read_bytes(),
        "firecracker": args.firecracker.read_bytes(),
        "firecracker.json": json.dumps(config).encode(),
        "inner.cpio": HELPERS["initramfs"](inner.read_bytes()),
        "inner-kernel": kernel.read_bytes(),
        "tmp/drive": b"ARM outer persistent marker\0".ljust(1 << 20, b"\0"),
    }))
    log = output / "guest.log"
    HELPERS["run"]([
        sys.executable, ROOT / "arm-parent-run.py", "--qemu", args.qemu, "--kernel", kernel,
        "--initrd", cpio, "--worker", args.bundle / "native-worker", "--mem", "384",
    ], 180, log)
    lines = log.read_text(errors="replace").splitlines()
    markers = (
        *(f"FLEXVM_ARM_INNER_CPU {cpu}" for cpu in range(args.vcpus)),
        "PASS ARM Firecracker virtio block read, write and flush",
        "PASS ARM Firecracker architected timer",
        "PASS stock ARM Firecracker used the parent-owned KVM device",
    )
    for marker in markers:
        if lines.count(marker) != 1:
            raise RuntimeError(f"missing or repeated {marker}; see {log}")
    report = {"status": "passed", "nested_vcpus": args.vcpus, "virtio_block": "read-write-flush",
              "arm_timer": "passed", "firecracker_sha256": HELPERS["digest"](args.firecracker)}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS stock ARM Firecracker executes through the parent KVM device")


if __name__ == "__main__":
    main()
