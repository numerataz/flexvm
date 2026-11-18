#!/usr/bin/env python3
"""Restore a stopped x86 worker onto freshly owned parent RAM."""
import argparse
from contextlib import contextmanager, ExitStack
import fcntl
import os
from pathlib import Path
import runpy
import struct
import tempfile
import time

ROOT = Path(__file__).resolve().parent
PARENT = runpy.run_path(str(ROOT / "parent-kvm-run.py"))
PAGE = PARENT["PAGE_SIZE"]
BASE = 0x1000
DATA = 0x200
PORT = 0x500
# Read the port, increment AL, then store and report it twice.
# Finally report the guest's configured CPUID leaf and halt.
PROGRAM = bytes.fromhex("ba0005 ec fec0 a20012 ee fec0 a20112 ee 66b800000040 0fa2 ba0005 66ef f4")
CPUID_LEAF = 0x40000000
CPUID_VALUE = 0x12345678
SIZE_SEALS = fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def backing(resources, name, size):
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    resources.callback(os.close, descriptor)
    os.ftruncate(descriptor, size)
    return descriptor


@contextmanager
def worker(qemu, state, ram, offset, incoming=None):
    with ExitStack() as resources:
        layout = backing(resources, "x86-checkpoint-layout", 8)
        os.pwrite(layout, struct.pack("<Q", offset), 0)
        fcntl.fcntl(layout, fcntl.F_ADD_SEALS, SIZE_SEALS | fcntl.F_SEAL_WRITE)
        try:
            child = PARENT["TcgChild"](
                qemu, state, state, ram, [layout], [PARENT["SlotLayout"](0, BASE, (offset,))],
                1, None, None, (), False, True, checkpoint=True, incoming=incoming,
            )
        except Exception:
            log = state / "child.log"
            if log.exists():
                print(log.read_text(errors="replace"))
            raise
        resources.callback(child.close)
        event = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
        resources.callback(os.close, event)

        def run(width=1):
            cancel = PARENT["RunCancellation"](event, None, 1, time.monotonic() + 5)
            result = child.run(0, cancel, b"")
            if result.reason != PARENT["KVM_EXIT_IO"] or result.address != PORT or result.width != width:
                raise RuntimeError(f"wrong checkpoint I/O exit: {result}")
            return result

        yield child, run


def exercise(qemu):
    with ExitStack() as resources:
        state = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="flexvm-x86-checkpoint-")))
        rom = bytearray(64 << 10)
        rom[-16] = 0xf4
        (state / "reset.rom").write_bytes(rom)
        source = backing(resources, "x86-checkpoint-source", 4 * PAGE)
        target = backing(resources, "x86-checkpoint-target", 4 * PAGE)
        for ram in (source, target):
            fcntl.fcntl(ram, fcntl.F_ADD_SEALS, SIZE_SEALS)
        start, destination = 2 * PAGE, PAGE
        os.pwrite(source, PROGRAM, start)
        marker = os.urandom(32)
        os.pwrite(source, marker, start + DATA + 32)
        snapshot = resources.enter_context(tempfile.TemporaryFile())
        with worker(qemu, state, source, start) as (child, run):
            registers = [0] * 18
            registers[16:18] = [BASE, 2]
            child.set_registers(0, PARENT["REGISTERS"].pack(*registers))
            child.set_cpuid(0, [(CPUID_LEAF, 0, 0, CPUID_VALUE, 0, 0, 0)])
            if run().is_write:
                raise RuntimeError("expected a live x86 port read")
            try:
                child.freeze_run_control(True)
            except RuntimeError as error:
                if "pending execution or I/O" not in str(error):
                    raise
            else:
                raise RuntimeError("checkpoint accepted a pending x86 port read")
            child.complete_read(0, b"\x29")
            result = run()
            if not result.is_write or result.data != b"\x2a":
                raise RuntimeError("x86 worker did not finish its completed input")
            frozen_registers = child.registers(0)
            child.freeze_run_control(True)
            cpuid_profiles = child.capture(snapshot.fileno())
        snapshot.seek(0)
        if marker in snapshot.read():
            raise RuntimeError("x86 worker stream duplicated external RAM")
        snapshot.seek(0)
        os.pwrite(target, os.pread(source, PAGE, start), destination)
        with worker(qemu, state, target, destination, incoming=(snapshot.fileno(), cpuid_profiles)) as (child, run):
            if child.registers(0) != frozen_registers:
                raise RuntimeError("x86 worker did not restore its stopped registers")
            child.freeze_run_control(False)
            result = run()
            if not result.is_write or result.data != b"\x2b":
                raise RuntimeError("restored x86 worker did not continue from the saved PC")
            reported = run(4)
            if not reported.is_write or reported.data != struct.pack("<I", CPUID_VALUE):
                raise RuntimeError("restored x86 guest lost its custom CPUID profile")
        if os.pread(target, 2, destination + DATA) != b"\x2a\x2b" or os.pread(source, 2, start + DATA) != b"\x2a\x00":
            raise RuntimeError("restored x86 worker wrote to the wrong RAM backing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    args = parser.parse_args()
    exercise(args.qemu.resolve(strict=True))
    print("PASS x86 TCG worker checkpoint retained CPU state and rebound external RAM")


if __name__ == "__main__":
    main()
