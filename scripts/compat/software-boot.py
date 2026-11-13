#!/usr/bin/env python3
"""Boot a real Linux kernel under TCG with host KVM masked in a private namespace.

This is an execution-engine acceptance check, not a FlexVM backend or KVM ABI provider.
Requires root, qemu-system for the native architecture, cc/static libc, unshare and strace.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent


class Interrupted(Exception):
    def __init__(self, number):
        self.number = number
        super().__init__(f"received signal {number}")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def initramfs(init, kvm=None, files=None):
    """Small uncompressed newc archive; no root-owned mknod or cpio executable needed."""
    archive = bytearray()

    def add(name, mode, data=b"", major=0, minor=0):
        name = name.encode() + b"\0"
        fields = (1, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(name), 0)
        archive.extend(b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + name)
        archive.extend(b"\0" * (-len(archive) % 4))
        archive.extend(data)
        archive.extend(b"\0" * (-len(archive) % 4))

    add("dev", 0o040755)
    add("dev/console", 0o020600, major=5, minor=1)
    add("init", 0o100755, init)
    if kvm is not None:
        add("dev/kvm", 0o020600, major=10, minor=232)
        add("kvm-abi", 0o100755, kvm)
    if files:
        for directory in ("proc", "sys", "tmp"):
            add(directory, 0o040755)
        for name, minor in (("null", 3), ("zero", 5), ("urandom", 9)):
            add("dev/" + name, 0o020600, major=1, minor=minor)
        for name, data in files.items():
            add(name, 0o100755 if name == "firecracker" else 0o100600, data)
    add("TRAILER!!!", 0)
    return archive


def run(argv, timeout, log):
    with log.open("wb") as output:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            result = proc.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            raise
    if result:
        raise RuntimeError(f"command exited {result}: {argv[0]}; see {log}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--guest-kvm", action="store_true", help="require ARM KVM execution inside software-emulated EL2")
    parser.add_argument("--guest-firecracker", type=Path, help="also boot an inner Linux VM with this unchanged ARM Firecracker binary (requires --guest-kvm)")
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root to mask host KVM inside a private mount namespace")
    arch = platform.machine()
    if arch not in ("x86_64", "aarch64"):
        parser.error(f"unsupported native architecture: {arch}")
    if args.guest_kvm and arch != "aarch64":
        parser.error("guest KVM execution currently targets ARM64 EL2")
    if args.guest_firecracker and not args.guest_kvm:
        parser.error("--guest-firecracker requires --guest-kvm")
    if args.timeout < 1:
        parser.error("timeout must be positive")
    kernel = args.kernel.resolve(strict=True)
    firecracker = args.guest_firecracker.resolve(strict=True) if args.guest_firecracker else None
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / "report.json"
    if report_path.exists():
        parser.error("output already has a report; use a new directory")
    report = {"schema_version": 1, "status": "running", "arch": arch, "accelerator": "tcg",
              "kernel_sha256": digest(kernel),
              "scope": "software guest KVM ABI execution" if args.guest_kvm else "execution-engine boot only"}
    if firecracker:
        report.update(scope="software guest hypervisor execution", firecracker_sha256=digest(firecracker))
    started = time.monotonic()

    def interrupted(number, _frame):
        raise Interrupted(number)

    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        init = out / "init"
        run([args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
             str(ROOT / "software-init.c"), "-o", str(init)], 60, out / "compile.log")
        archive = out / "initramfs.cpio"
        nested = None
        if args.guest_kvm:
            test = out / "kvm-abi"
            run([args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                 str(ROOT / "kvm-arm.c"), "-o", str(test)], 60, out / "kvm-compile.log")
            nested = test.read_bytes()
        files = None
        if firecracker:
            inner = out / "inner-init"
            run([args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                 str(ROOT / "nested-init.c"), "-o", str(inner)], 60, out / "inner-compile.log")
            config = {"boot-source": {"kernel_image_path": "/inner-kernel",
                                      "initrd_path": "/inner-initramfs.cpio",
                                      "boot_args": "console=ttyS0 quiet panic=1 rdinit=/init"},
                      "machine-config": {"vcpu_count": 1, "mem_size_mib": 128},
                      "drives": [], "network-interfaces": []}
            files = {"firecracker": firecracker.read_bytes(), "inner-kernel": kernel.read_bytes(),
                     "inner-initramfs.cpio": initramfs(inner.read_bytes()),
                     "firecracker.json": json.dumps(config).encode()}
        archive.write_bytes(initramfs(init.read_bytes(), nested, files))
        blocked = out / "unusable-kvm"
        blocked.touch(mode=0o600)
        qemu = "qemu-system-" + arch
        machine, console = ("q35", "ttyS0") if arch == "x86_64" else ("virt", "hvc0")
        serial = ["-nographic"]
        if arch == "aarch64":
            # The reviewed Firecracker ARM kernel has virtio-console, not PL011.
            serial = ["-display", "none", "-monitor", "none", "-serial", "none",
                      "-chardev", "stdio,id=console,signal=off",
                      "-device", "virtio-serial-device,id=serial",
                      "-device", "virtconsole,chardev=console,bus=serial.0"]
        if args.guest_kvm:
            machine += ",virtualization=on,gic-version=3"
        cmd = [qemu, "-machine", machine, "-accel", "tcg,thread=multi", "-cpu", "max",
               "-m", "512" if firecracker else "256", "-smp", "1", *serial, "-no-reboot", "-nic", "none",
               "-kernel", str(kernel), "-initrd", str(archive),
               "-append", f"console={console} quiet panic=1 rdinit=/init"]
        trace = out / "files.strace"
        # The bind mount affects only this process tree. If /dev/kvm exists it
        # becomes a regular file, so it cannot provide KVM ioctls even to root.
        isolated = ["unshare", "--mount", "--propagation", "private", "sh", "-ec",
                    'if [ -e /dev/kvm ]; then mount --bind "$1" /dev/kvm; fi; shift; exec "$@"',
                    "sh", str(blocked), "strace", "-f", "-e", "trace=file", "-o", str(trace), *cmd]
        run(isolated, args.timeout, out / "guest.log")
        log = (out / "guest.log").read_text(errors="replace")
        expected = ["FLEXVM_SOFTWARE_GUEST_BOOTED", "FLEXVM_SOFTWARE_GUEST_COMPLETE"]
        expected += [f"FLEXVM_SOFTWARE_GUEST_TICK {i}" for i in range(3)]
        if args.guest_kvm:
            expected.append("FLEXVM_SOFTWARE_GUEST_KVM_PASSED")
        if firecracker:
            expected += ["FLEXVM_SOFTWARE_INNER_BOOTED", "FLEXVM_SOFTWARE_INNER_COMPLETE",
                         "FLEXVM_SOFTWARE_GUEST_FIRECRACKER_PASSED"]
            expected += [f"FLEXVM_SOFTWARE_INNER_TICK {i}" for i in range(3)]
        if any(marker not in log for marker in expected):
            raise RuntimeError("guest did not finish its boot/timer/shutdown checks; see guest.log")
        if '"/dev/kvm"' in trace.read_text(errors="replace"):
            raise RuntimeError("software execution attempted to access /dev/kvm; see files.strace")
        report.update(status="passed", guest_init_sha256=digest(init), kvm_access=False, guest_kvm=args.guest_kvm)
        if firecracker:
            report.update(guest_firecracker=True, inner_init_sha256=digest(inner))
    except Interrupted as exc:
        report.update(status="interrupted", error=str(exc), signal=exc.number)
    except Exception as exc:
        report.update(status="failed", error=str(exc))
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        report["elapsed_s"] = round(time.monotonic() - started, 3)
        report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}: {report_path}")
    if report["status"] == "interrupted":
        return 128 + report["signal"]
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
