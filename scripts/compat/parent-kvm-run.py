#!/usr/bin/env python3
"""One x86 KVM I/O exit via a parent TCG worker and a guest PCI mailbox."""
import argparse
import errno
import json
import mmap
import os
from pathlib import Path
import platform
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
SOURCES = ROOT / "parent-kvm"
HELPERS = runpy.run_path(str(ROOT / "software-boot.py"))
DEVICES = ("/dev/kvm", "/dev/vhost-vsock", "/dev/vhost-net")
MIB = 1 << 20
MAILBOX_SIZE = 64 << 10
RAM_AT = 4096
IO_VALUE = 0x42
OPEN_VM, CLOSE_VM, OPEN_CPU, CLOSE_CPU, RUN = range(1, 6)
QEMU_OPTIONS = [
    "-nodefaults", "-display", "none", "-monitor", "none", "-nic", "none",
    "-smp", "1", "-no-reboot", "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
]


def execute_child(qemu, output, code):
    ram = os.memfd_create("flexvm-parent-kvm-run", os.MFD_CLOEXEC)
    try:
        os.ftruncate(ram, 16 * MIB)
        os.pwrite(ram, code, RAM_AT)
        memory = f"memory-backend-file,id=ram,mem-path=/proc/self/fd/{ram},share=on,size=16M"
        command = [
            qemu, *QEMU_OPTIONS, "-machine", "pc,accel=tcg,memory-backend=ram", "-m", "16", "-serial", "none",
            "-object", memory, "-device", "isa-debug-exit,iobase=0x30,iosize=1", "-bios", output / "reset.rom",
        ]
        with (output / "child.log").open("wb") as log:
            child = subprocess.run(command, pass_fds=(ram,), stdout=log, stderr=log, timeout=3)
        # The debug-exit device encodes the port write in the host process status.
        if child.returncode != (IO_VALUE << 1) | 1:
            raise RuntimeError(f"unexpected child exit status {child.returncode}")
        return child.returncode >> 1, os.pread(ram, len(code), RAM_AT)
    finally:
        os.close(ram)


def exercise(qemu, kernel, output):
    reset = bytearray(64 << 10)
    # The reset vector far-jumps to 0000:1000, the client's guest RAM.
    reset[0xfff0:0xfff5] = bytes.fromhex("ea00100000")
    (output / "reset.rom").write_bytes(reset)
    mailbox = output / "mailbox"
    command = [
        qemu, *QEMU_OPTIONS, "-machine", "q35,accel=tcg", "-cpu", "max,vmx=off,svm=off", "-m", "192",
        "-serial", "stdio", "-kernel", kernel, "-initrd", output / "initramfs",
        "-append", "console=ttyS0 quiet panic=1 rdinit=/init",
        "-object", f"memory-backend-file,id=mailbox,mem-path={mailbox},share=on,size=64K",
        "-device", "ivshmem-plain,memdev=mailbox",
    ]
    expected = (OPEN_VM, OPEN_CPU, RUN, CLOSE_CPU, CLOSE_VM)
    observed = []
    io_value = None
    with mailbox.open("w+b") as backing:
        backing.truncate(MAILBOX_SIZE)
        with mmap.mmap(backing.fileno(), MAILBOX_SIZE) as mapping, (output / "outer.log").open("wb") as log:
            struct.pack_into("<II", mapping, 0, 0x4d564b46, 1)
            outer = subprocess.Popen(command, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 60
                while outer.poll() is None and time.monotonic() < deadline:
                    pending, complete, opcode, _, length = struct.unpack_from("<IIIII", mapping, 8)
                    if pending == complete:
                        time.sleep(.001)
                        continue
                    status = -errno.EINVAL
                    if (pending == complete + 1 and len(observed) < len(expected)
                            and opcode == expected[len(observed)] and length == (4096 if opcode == RUN else 0)):
                        if opcode == RUN:
                            io_value, data = execute_child(qemu, output, mapping[RAM_AT:RAM_AT + length])
                            mapping[RAM_AT:RAM_AT + length] = data
                            struct.pack_into("<I", mapping, 28, io_value)
                        observed.append(opcode)
                        status = 0
                    struct.pack_into("<i", mapping, 20, status)
                    struct.pack_into("<I", mapping, 12, pending)
                if outer.poll() is None:
                    raise TimeoutError("outer guest did not shut down")
                guest = (output / "outer.log").read_text(errors="replace")
                if (outer.returncode != 0 or tuple(observed) != expected or io_value != IO_VALUE
                        or "PASS /dev/kvm returned the expected port I/O exit" not in guest
                        or "PASS parent KVM guest shutdown" not in guest):
                    raise RuntimeError(f"parent execution proof failed; commands={observed}, see outer.log")
            finally:
                if outer.poll() is None:
                    outer.kill()
                outer.wait()
    return {
        "guest_path": "/dev/kvm", "guest_vmx": False, "guest_svm": False,
        "parent_accelerator": "tcg", "parent_commands": observed,
        "io_value": io_value, "child_memory_write_visible": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--kernel-build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-oracle", action="store_true")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    qemu, kernel = (path.resolve(strict=True) for path in (args.qemu, args.kernel))
    output = args.output.resolve()
    if os.geteuid() != 0 or platform.machine() != "x86_64":
        parser.error("run as root on x86_64")
    if args.worker:
        print(json.dumps(exercise(qemu, kernel, output)))
        return 0
    if args.kernel_build is None:
        parser.error("--kernel-build needs the development tree matching --kernel")
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    if report_path.exists():
        parser.error("use an output directory without an existing report")
    report = {"qemu_sha256": HELPERS["digest"](qemu), "kernel_sha256": HELPERS["digest"](kernel)}
    try:
        module = output / "module"
        module.mkdir()
        for filename in ("Makefile", "mailbox.h", "flexvm-pvkvm.c"):
            shutil.copyfile(SOURCES / filename, module / filename)
        HELPERS["run"](["make", "-j2", "-C", args.kernel_build.resolve(strict=True), f"M={module}", "modules"],
                       120, output / "module-build.log")
        client, init = output / "client", output / "init"
        for source, binary in (("kvm-run.c", client), ("init.c", init)):
            HELPERS["run"](["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", SOURCES / source, "-o", binary],
                           20, output / f"{source}.log")
        report.update(client_sha256=HELPERS["digest"](client), module_sha256=HELPERS["digest"](module / "flexvm-pvkvm.ko"))
        if args.native_oracle:
            HELPERS["run"]([client], 8, output / "native-kvm.log")
            report["same_client_passed_native_kvm"] = True
        image = HELPERS["initramfs"](init.read_bytes(), files={
            "kvm-run": client.read_bytes(), "flexvm-pvkvm.ko": (module / "flexvm-pvkvm.ko").read_bytes(),
        })
        (output / "initramfs").write_bytes(image)
        trace = output / "files.strace"
        worker = output / "worker.log"
        setup = """
            for path in /dev/kvm /dev/vhost-vsock /dev/vhost-net; do
                if [ -e "$path" ]; then mount --bind "$1" "$path"; fi
            done
            shift
            exec "$@"
        """
        with tempfile.TemporaryDirectory(prefix="flexvm-parent-kvm-") as scratch:
            mask = Path(scratch) / "mask"
            mask.touch(mode=0o600)
            HELPERS["run"](["unshare", "--mount", "--propagation", "private", "sh", "-ec", setup, "sh", mask,
                            "strace", "-f", "-e", "trace=file", "-o", trace, sys.executable,
                            Path(__file__).resolve(), "--worker", "--qemu", qemu, "--kernel", kernel,
                            "--output", output], 75, worker)
        with trace.open(errors="replace") as lines:
            if any(f'"{device}"' in line for line in lines for device in DEVICES):
                raise RuntimeError("host virtualization device access under the mask")
        report.update(json.loads(worker.read_text()), status="passed", host_device_access=False)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=str(error))
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}: {report_path}")
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
