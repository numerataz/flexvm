#!/usr/bin/env python3
"""Round-trip the fenced native x86 worker's core and interrupt state."""
import argparse
from contextlib import ExitStack, contextmanager
import errno
import fcntl
import os
from pathlib import Path
import runpy
import select
import shutil
import struct

PARENT = runpy.run_path(str(Path(__file__).with_name("parent-kvm-run.py")))
BASE = 0x1000
PORT = 0x500
LEAF = 0x40000000
VALUE = 0x12345678
# Load AL, report it, and stay in a loop after the I/O exit is completed.
PROGRAM = bytes.fromhex("ba0005 b021 ee ebfe")
# Continue at the same guest RIP and report the retained AL and CPUID.
CONTINUE = bytes.fromhex("fec0 ee 66b800000040 0fa2 ba0005 66ef f4")


def memfd(stack, name, size):
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    stack.callback(os.close, descriptor)
    os.ftruncate(descriptor, size)
    return descriptor


@contextmanager
def boot(output, binary, ram, offset):
    output.mkdir()
    worker = output / PARENT["NATIVE_WORKER"]
    worker.parent.mkdir(parents=True)
    shutil.copyfile(binary, worker)
    worker.chmod(0o700)
    with ExitStack() as owned:
        layout = memfd(owned, "x86-native-slot", 8)
        os.pwrite(layout, struct.pack("<Q", offset), 0)
        fcntl.fcntl(layout, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE)
        interrupts = tuple(os.eventfd(0, os.EFD_NONBLOCK | os.EFD_CLOEXEC) for _ in range(PARENT["GSI_COUNT"]))
        for fd in interrupts:
            owned.callback(os.close, fd)
        child = PARENT["KvmChild"](output, ram, [layout], [PARENT["SlotLayout"](0, BASE, (offset,))],
                                   1, True, PARENT["KVM_PIT_SPEAKER_DUMMY"], interrupts, None, True)
        owned.callback(child.close)
        replies = os.eventfd(0, os.EFD_NONBLOCK | os.EFD_CLOEXEC)
        owned.callback(os.close, replies)
        mailbox = bytearray(PARENT["MAILBOX_SIZE"])
        lane = PARENT["LANES_AT"]

        def begin(sequence):
            struct.pack_into("<I", mailbox, lane, sequence)
            struct.pack_into("<I", mailbox, lane + 8, PARENT["RUN"])
            child.lanes.service(mailbox, (), {0}, {0}, replies)

        def finish(sequence, status=0, *, hold=False):
            if hold:
                child.lanes.service(mailbox, (), {0}, {0}, replies, hold=True)
            readable, _, _ = select.select(child.lanes.descriptors(), (), (), 5)
            if not readable:
                raise RuntimeError("native worker did not reply")
            child.lanes.service(mailbox, readable, {0}, {0}, replies, hold=hold)
            if (os.eventfd_read(replies) != 1 or struct.unpack_from("<I", mailbox, lane + 4)[0] != sequence or
                    struct.unpack_from("<i", mailbox, lane + 12)[0] != status):
                raise RuntimeError("unexpected native worker run reply")

        yield child, begin, finish


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir()
    page = PARENT["PAGE_SIZE"]
    with ExitStack() as owned:
        state = memfd(owned, "x86-native-state", 0)
        source = memfd(owned, "x86-native-source", page)
        target = memfd(owned, "x86-native-target", page * 2)
        for ram in (source, target):
            fcntl.fcntl(ram, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        os.pwrite(source, PROGRAM, 0)
        with boot(args.output / "source", args.worker, source, 0) as (child, begin, finish):
            regs = [0] * 18
            regs[16:] = [BASE, 2]
            child.set_registers(0, PARENT["REGISTERS"].pack(*regs))
            child.set_cpuid(0, [(LEAF, 0, 0, VALUE, 0, 0, 0)])
            begin(1)
            finish(1)
            if child.lanes.written_pio != [(PORT, 1, b"\x21")]:
                raise RuntimeError("native source did not reach the first I/O exit")
            begin(2)
            # Observe entry into the loop before sending the cancellation.
            # A cancelled vCPU may otherwise report an interrupt before entry.
            select.select(child.lanes.descriptors(), (), (), .02)
            finish(2, -errno.EINTR, hold=True)
            child.freeze_run_control(True)
            original = child.registers(0)
            child.checkpoint_file(state)

        os.pwrite(target, os.pread(source, page, 0), page)
        os.pwrite(target, CONTINUE, page + len(PROGRAM) - 2)
        with boot(args.output / "target", args.worker, target, page) as (child, begin, finish):
            child.freeze_run_control(True)
            fresh = child.registers(0)
            bad = memfd(owned, "x86-native-invalid-state", os.fstat(state).st_size)
            os.pwrite(bad, os.pread(state, os.fstat(state).st_size, 0), 0)
            os.pwrite(bad, b"INVALID!", 0)
            try:
                child.checkpoint_file(bad, restore=True)
            except OSError as error:
                if error.errno != errno.EINVAL:
                    raise
            else:
                raise RuntimeError("native worker accepted an invalid state header")
            if child.registers(0) != fresh:
                raise RuntimeError("invalid snapshot modified a fresh vCPU")
            child.checkpoint_file(state, restore=True)
            if child.registers(0) != original:
                raise RuntimeError("native target did not recover the exact source registers")
            child.freeze_run_control(False)
            begin(1)
            finish(1)
            begin(2)
            finish(2)
            if child.lanes.written_pio != [(PORT, 1, b"\x22"), (PORT, 4, struct.pack("<I", VALUE))]:
                raise RuntimeError(f"native target lost CPU or CPUID state: {child.lanes.written_pio!r}")
    print("PASS native x86 worker restored registers and CPUID on different parent RAM")


if __name__ == "__main__":
    main()
