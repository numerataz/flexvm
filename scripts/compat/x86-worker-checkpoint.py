#!/usr/bin/env python3
"""Restore a stopped x86 worker onto freshly owned parent RAM."""
import argparse
from contextlib import contextmanager, ExitStack
import errno
import fcntl
import os
from pathlib import Path
import runpy
import select
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


def settle_run_lanes(child, registers):
    lanes = child.lanes
    mailbox = bytearray(PARENT["MAILBOX_SIZE"])
    offset = PARENT["LANES_AT"]
    replies = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
    try:
        def service(*, hold=False, ready=()):
            lanes.service(mailbox, ready, {0}, {0}, replies, hold=hold)

        def issue(sequence):
            struct.pack_into("<I", mailbox, offset, sequence)
            struct.pack_into("<I", mailbox, offset + 8, PARENT["RUN"])

        def acknowledged(sequence, status):
            if os.eventfd_read(replies) != 1 or struct.unpack_from("<I", mailbox, offset + 4)[0] != sequence:
                raise RuntimeError("x86 checkpoint lost its run-lane acknowledgment")
            if struct.unpack_from("<i", mailbox, offset + 12)[0] != status:
                raise RuntimeError("x86 checkpoint reported the wrong run-lane status")

        def finish(*, hold=False):
            ready, _, _ = select.select(lanes.descriptors(), (), (), 5)
            if not ready:
                raise RuntimeError("x86 checkpoint did not receive a run-lane reply")
            service(hold=hold, ready=ready)

        def provide_input(value):
            PARENT["COMPLETION_RECORD"].pack_into(mailbox, offset + PARENT["LANE_COMPLETION"], 1, 0, bytes(8))
            mailbox[offset + PARENT["LANE_PIO"]] = value

        def clear_input():
            PARENT["COMPLETION_RECORD"].pack_into(mailbox, offset + PARENT["LANE_COMPLETION"], 0, 0, bytes(8))

        # Cancel a live run that already carried a read completion to the worker.
        spin = list(registers)
        spin[16] = BASE + 0x100
        child.set_registers(0, PARENT["REGISTERS"].pack(*spin))
        issue(1)
        service()
        finish()
        acknowledged(1, 0)
        issue(2)
        provide_input(73)
        service()
        if lanes.checkpoint_ready():
            raise RuntimeError("active x86 run lane was reported as fenced")
        service(hold=True)
        finish(hold=True)
        acknowledged(2, -errno.EINTR)
        if PARENT["REGISTERS"].unpack(child.registers(0))[0] & 0xff != 73:
            raise RuntimeError("x86 cancellation dropped an already submitted port read")

        child.set_registers(0, PARENT["REGISTERS"].pack(*registers))
        issue(3)
        clear_input()
        service()
        finish()
        acknowledged(3, 0)
        if lanes.checkpoint_ready():
            raise RuntimeError("x86 port read was reported as complete")
        try:
            child.freeze_run_control(True)
        except RuntimeError as error:
            if "pending execution or I/O" not in str(error):
                raise
        else:
            raise RuntimeError("checkpoint accepted a pending x86 port read")

        # Complete the existing read during the fence, without new execution.
        issue(4)
        provide_input(41)
        service(hold=True)
        finish(hold=True)
        acknowledged(4, -errno.EINTR)
        if not lanes.checkpoint_ready():
            raise RuntimeError("the completed x86 port read retained a live lane")

        # Keep rejecting new KVM_RUN requests while the owner is fenced.
        issue(5)
        clear_input()
        service(hold=True)
        acknowledged(5, -errno.EINTR)
        if not lanes.checkpoint_ready():
            raise RuntimeError("held x86 KVM_RUN started another run")
    finally:
        os.close(replies)


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
        os.pwrite(source, bytes.fromhex("ba0005 ec ebfe"), start + 0x100)
        marker = os.urandom(32)
        os.pwrite(source, marker, start + DATA + 32)
        snapshot = resources.enter_context(tempfile.TemporaryFile())
        with worker(qemu, state, source, start) as (child, run):
            registers = [0] * 18
            registers[16:18] = [BASE, 2]
            child.set_cpuid(0, [(CPUID_LEAF, 0, 0, CPUID_VALUE, 0, 0, 0)])
            settle_run_lanes(child, registers)
            result = run()
            if not result.is_write or result.data != b"\x2a":
                raise RuntimeError("x86 worker did not finish its completed input")
            frozen_registers = child.registers(0)
            child.freeze_run_control(True)
            clock = child.capture_clock()
            time.sleep(.05)
            if child.capture_clock() != clock:
                raise RuntimeError("the fenced x86 worker clock advanced")
            worker_state = child.capture(snapshot.fileno())
        snapshot.seek(0)
        if marker in snapshot.read():
            raise RuntimeError("x86 worker stream duplicated external RAM")
        snapshot.seek(0)
        os.pwrite(target, os.pread(source, PAGE, start), destination)
        with worker(qemu, state, target, destination, incoming=(snapshot.fileno(), worker_state)) as (child, run):
            if child.registers(0) != frozen_registers:
                raise RuntimeError("x86 worker did not restore its stopped registers")
            if child.capture_clock() != clock:
                raise RuntimeError("x86 worker did not restore its stopped clock")
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
