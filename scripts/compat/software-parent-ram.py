#!/usr/bin/env python3
"""Exercise shared RAM between two isolated x86 QEMU TCG workers."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import runpy
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / "software-boot.py"))
DEVICES = ("/dev/kvm", "/dev/vhost-vsock", "/dev/vhost-net")
MIB = 1 << 20
CHILD_OFFSET = 16 * MIB
CHILD_CELL = 0x80000
OUTER_CELL = CHILD_OFFSET + CHILD_CELL


def exercise(qemu, directory):
    ram = os.memfd_create("flexvm-parent-ram", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    workers = []

    def start(label, mib, offset):
        memory = f"memory-backend-file,id=ram,size={mib}M,mem-path=/proc/self/fd/{ram},share=on,offset={offset}"
        args = [
            qemu, "-nodefaults", "-display", "none", "-monitor", "none", "-serial", "none",
            "-no-reboot", "-smp", "1", "-m", str(mib), "-bios", directory / f"{label}.rom",
            "-machine", "pc,accel=tcg,memory-backend=ram", "-object", memory,
            "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        ]
        with (directory / f"{label}.log").open("wb") as log:
            process = subprocess.Popen(args, pass_fds=(ram,), stdout=log, stderr=log)
        workers.append(process)
        return process

    def cell(offset):
        return struct.unpack("<I", os.pread(ram, 4, offset))[0]

    try:
        os.ftruncate(ram, 32 * MIB)
        fcntl.fcntl(ram, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        outer = start("outer", 32, 0)
        deadline = time.monotonic() + 10
        while cell(OUTER_CELL) != 0x11223344:
            if outer.poll() is not None:
                raise RuntimeError(f"outer worker exited before writing ({outer.returncode})")
            if time.monotonic() >= deadline:
                raise TimeoutError("outer worker did not write to shared RAM")
            time.sleep(.005)
        started = time.monotonic()
        child = start("child", 16, CHILD_OFFSET)
        # isa-debug-exit reports (guest_value << 1) | 1 as the process status.
        child_status = child.wait(timeout=10)
        outer_status = outer.wait(timeout=10)
        if (child_status, outer_status) != (33, 35):
            raise RuntimeError(f"worker exit status child={child_status}, outer={outer_status}")
        if cell(OUTER_CELL) != 0x55667788 or cell(CHILD_CELL) != 0:
            raise RuntimeError("worker did not write through the offset mapping")
        return {
            "outer_cpu_observed_child_write": True,
            "child_cpu_observed_outer_write": True,
            "control_cell_unchanged": True,
            "child_start_to_both_exited_ms": round((time.monotonic() - started) * 1000, 2),
        }
    finally:
        for process in workers:
            if process.poll() is None:
                process.kill()
            process.wait()
        os.close(ram)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    qemu, output = args.qemu.resolve(strict=True), args.output.resolve()
    if os.geteuid() != 0 or platform.machine() != "x86_64":
        parser.error("run as root on x86_64")
    if args.worker:
        print(json.dumps(exercise(qemu, output)))
        return 0
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    if report_path.exists():
        parser.error("use an output directory without an existing report")
    report = {"qemu_sha256": HELPERS["digest"](qemu)}
    try:
        for label, value in (("outer", 0), ("child", 1)):
            obj = output / f"{label}.o"
            HELPERS["run"](["as", "--32", "--defsym", f"CHILD={value}", ROOT / "software-parent-ram.S", "-o", obj],
                           15, output / f"{label}-assemble.log")
            HELPERS["run"](["ld", "-m", "elf_i386", "-Ttext=0", "-e", "0", "--oformat", "binary", obj, "-o", output / f"{label}.rom"],
                           15, output / f"{label}-link.log")
        trace = output / "files.strace"
        setup = """
            for path in /dev/kvm /dev/vhost-vsock /dev/vhost-net; do
                if [ -e "$path" ]; then mount --bind "$1" "$path"; fi
            done
            shift
            exec "$@"
        """
        with tempfile.TemporaryDirectory(prefix="flexvm-parent-ram-") as scratch:
            mask = Path(scratch) / "mask"
            mask.touch(mode=0o600)
            worker = output / "worker.log"
            HELPERS["run"](["unshare", "--mount", "--propagation", "private", "sh", "-ec", setup, "sh", mask,
                            "strace", "-f", "-e", "trace=file", "-o", trace,
                            sys.executable, Path(__file__).resolve(), "--worker", "--qemu", qemu, "--output", output], 35, worker)
        with trace.open(errors="replace") as lines:
            if any(f'"{device}"' in line for line in lines for device in DEVICES):
                raise RuntimeError("host virtualization device access")
        report.update(json.loads(worker.read_text()), status="passed", host_device_access=False)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=str(error))
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}: {report_path}")
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
