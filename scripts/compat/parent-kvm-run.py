#!/usr/bin/env python3
"""Run a parent worker against a pinned KVM memory slot in shared outer RAM."""
import argparse
from contextlib import ExitStack, contextmanager
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import json
import mmap
import os
from pathlib import Path
import platform
import re
import runpy
import select
import shutil
import signal
import socket
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
MAILBOX_SIZE = 1 << 20
PAGE_SIZE = 4096
MAX_REAL_MODE_PAGES = 128
MAX_SLOT_PAGES = 65536
PROTECTED_GPA = 16 * MIB
SPLIT_GPA = 512 * MIB
MAX_SLOTS = 8
TEST_INTERRUPTS = 3
CR0_PAGING = 1 << 31
CR4_PAE = 1 << 5
EFER_LONG_MODE_ACTIVE = 1 << 10
EFER_LONG_MODE_ENABLE = 1 << 8
(OPEN_VM, CLOSE_VM, OPEN_CPU, CLOSE_CPU, RUN, GET_REGS, SET_REGS, GET_SREGS,
 GET_FPU, SET_FPU, GET_MSRS, SET_MSRS, GET_SUPPORTED_CPUID, CREATE_IRQCHIP, SET_IRQ_LINE,
 CREATE_PIT, SET_TSS_ADDR, GET_LAPIC, SET_LAPIC, COMPLETE_READ, GET_IRQCHIP, SET_IRQCHIP,
 GET_PIT, SET_PIT, GET_DEBUGREGS, SET_DEBUGREGS, GET_MP_STATE, SET_MP_STATE,
 GET_XCRS, SET_XCRS, GET_XSAVE, SET_XSAVE, GET_VCPU_EVENTS, SET_VCPU_EVENTS) = range(1, 35)
FPU_VALID_AT = 48
FPU_AT = 768
FPU_SIZE = 416
RAM_ADDRESS_AT = 1280
MSR_AT = 0x81000
MSR_BATCH_MAX = 64
MSR_HEADER = struct.Struct("<II")
MSR_ENTRY = struct.Struct("<IIQ")
CPUID_VALID_AT = 52
CPUID_AT = 0x82000
CPUID_MAX = 128
CPUID_HEADER = struct.Struct("<II")
CPUID_ENTRY = struct.Struct("<7I12x")
CPUID_BYTES = CPUID_HEADER.size + CPUID_ENTRY.size * CPUID_MAX
CPUID_FIELDS = ("function", "index", "indexed", "eax", "ebx", "ecx", "edx")
TCG_CHILD_CPU = "qemu64,+xsave,+avx"
KVM_EXIT_IO = 2
KVM_EXIT_MMIO = 6
IO_PORT = 0x30
MMIO_BASE = 0xd0000000
MMIO_WIRE = struct.Struct("<cBQ8s")
PIO_HEADER = struct.Struct("<cBHI")
PIO_DATA_AT = 0x86000
PIO_BYTES = 4096
IRQCHIP_AT = 0x87000
IRQCHIP_SIZE = 520
IRQCHIP_HEADER = struct.Struct("<II")
IRQCHIP_PAYLOAD_SIZES = (16, 16, 216)
PIT_STATE_AT = 0x87300
PIT_STATE_SIZE = 112
DEBUGREGS_AT = 0x87400
DEBUGREGS = struct.Struct("<6Q80x")
DEBUGREGS_FIELDS = ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")
MP_STATE_AT = 0x87480
MP_STATE = struct.Struct("<I")
MP_STATE_REPLY = struct.Struct("<iI")
MP_RUNNABLE = 0
MP_INIT_RECEIVED = 2
MP_SIPI_RECEIVED = 4
XCRS_AT = 0x87500
XCRS = struct.Struct("<4IQ368x")
IOCTL_RESULT = struct.Struct("<i")
XSAVE_AT = 0x88000
XSAVE_SIZE = 4096
VCPU_EVENTS_AT = 0x89000
VCPU_EVENTS_SIZE = 64
VCPU_EVENT_FLAGS = 20
EVENT_NMI_PENDING = 1
EVENT_SIPI_VECTOR = 2
EVENT_SHADOW = 4
EVENT_SMM = 8
PIO_WRITES = ((0x3f8, 1, b"L"), (0x2f8, 2, b"\xcd\xab"),
              (0xcf8, 4, b"\x00\x00\x00\x80"), (0x3f8, 1, b"vmio"))
PIO_READS = ((0x3fd, 1, b"\x60"), (0x2f8, 2, b"\x67\x45"),
             (0xcfc, 4, b"\xef\xbe\x34\x12"), (0x2f8, 1, b"data"))
PIO_BOUNDARY_WRITES = ((0x1e, 4, b"\xe8\x39\x63\x1a"), (0xfffe, 4, b"\x01\x02\x03\x04"))
PIO_BOUNDARY_READS = ((0x21, 2, b"\x55\x33"), (0xffff, 4, b"\xde\xc0\xef\xbe"))
EXIT_AT = 0x84000
EXIT_RECORD = struct.Struct("<IIQ8sII")
COMPLETION_AT = 0x84100
COMPLETION_RECORD = struct.Struct("<II8s")
IRQ_AT = 0x84200
IRQ_RECORD = struct.Struct("<II")
PIT_FLAGS_AT = 0x84208
TSS_AT = 0x8420c
LAPIC_AT = 0x85000
LAPIC_VALID_AT = 56
LAPIC_SIZE = 1024
FIRECRACKER_TSS_GPA = 0xfffbd000
KVM_PIT_SPEAKER_DUMMY = 1
GSI_COUNT = 24
IRQ_LEVELS = [(3, 0), (3, 1), (3, 0)]
MMIO_WRITES = (
    (MMIO_BASE + 0x10, b"\x39"),
    (MMIO_BASE + 0x14, b"\x09\x87\x65\x43"),
    (MMIO_BASE + 0x18, b"\x88\x77\x66\x55\x44\x33\x22\x11"),
)
MMIO_READS = (
    (MMIO_BASE + 0x24, b"\x22\x33\x44\x5a"),
    (MMIO_BASE + 0x28, b"\x11\x00\xff\xee\xdd\xcc\xbb\xaa"),
)
# Linux's x86 struct kvm_regs.
REGISTERS = struct.Struct("<18Q")
SEGMENT = struct.Struct("<QIH9Bx")
DESCRIPTOR_TABLE = struct.Struct("<QH6x")
CONTROL_REGISTERS = struct.Struct("<7Q32x")
SPECIAL_REGISTERS_SIZE = 8 * SEGMENT.size + 2 * DESCRIPTOR_TABLE.size + CONTROL_REGISTERS.size
# (GDB index, KVM index, bytes) from QEMU's i386-64bit.xml.
GDB_REGISTERS = (
    (0, 0, 8), (1, 1, 8), (2, 2, 8), (3, 3, 8), (4, 4, 8), (5, 5, 8),
    (6, 7, 8), (7, 6, 8), *((index, index, 8) for index in range(8, 17)), (17, 17, 4),
)
QEMU_OPTIONS = [
    "-nodefaults", "-display", "none", "-monitor", "none", "-nic", "none",
    "-no-reboot", "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
]


@dataclass(frozen=True)
class SlotLayout:
    identifier: int
    gpa: int
    offsets: tuple[int, ...]


@dataclass(frozen=True)
class RunCancellation:
    descriptor: int
    mailbox: mmap.mmap
    sequence: int
    deadline: float

    def applies(self):
        os.eventfd_read(self.descriptor)
        sequence, = struct.unpack_from("<I", self.mailbox, 40)
        if sequence > self.sequence:
            raise RuntimeError("cancelled a future run")
        return sequence == self.sequence


@dataclass(frozen=True)
class RunExit:
    reason: int
    address: int
    data: bytes
    is_write: bool = True
    count: int = 1

    @property
    def width(self):
        return len(self.data) // self.count

    def record(self):
        return EXIT_RECORD.pack(self.reason, self.width, self.address, self.data[:8], self.is_write, self.count)


def pio_size(width, count):
    if width not in (1, 2, 4) or not 0 < count <= PIO_BYTES // width:
        raise RuntimeError("invalid worker port I/O size")
    return width * count


def coalesce_pio(records):
    groups = []
    for port, width, data in records:
        if groups and (port, width) == groups[-1][:2]:
            groups[-1] = (port, width, groups[-1][2] + data)
        else:
            groups.append((port, width, data))
    return tuple(groups)


def read_completion(mailbox, pending, pio_reads, mmio_reads):
    size, reserved, value = COMPLETION_RECORD.unpack_from(mailbox, COMPLETION_AT)
    if reserved or size != (len(pending.data) if pending else 0):
        raise RuntimeError("guest changed the outstanding I/O read size")
    if pending is None:
        return b""
    if pending.reason == KVM_EXIT_IO:
        completion = mailbox[PIO_DATA_AT:PIO_DATA_AT + size]
        pio_reads.append((pending.address, pending.width, completion))
    else:
        completion = value[:size]
        mmio_reads.append((pending.address, completion))
    return completion


class SignalValue(ctypes.Union):
    _fields_ = [("integer", ctypes.c_int), ("pointer", ctypes.c_void_p)]


def pack_special_registers(snapshot):
    if len(snapshot["segments"]) != 8:
        raise RuntimeError("QEMU did not return eight x86 segment caches")
    segments = []
    for segment in snapshot["segments"]:
        flags = segment["flags"]
        present = (flags >> 15) & 1
        segments.append(SEGMENT.pack(segment["base"], segment["limit"], segment["selector"],
                                     (flags >> 8) & 15, present, (flags >> 13) & 3,
                                     (flags >> 22) & 1, (flags >> 12) & 1, (flags >> 21) & 1,
                                     (flags >> 23) & 1, (flags >> 20) & 1, 1 - present))
    gdt = DESCRIPTOR_TABLE.pack(snapshot["gdt-base"], snapshot["gdt-limit"])
    idt = DESCRIPTOR_TABLE.pack(snapshot["idt-base"], snapshot["idt-limit"])
    # The fixture has no external interrupt injection, so the bitmap stays zero.
    controls = CONTROL_REGISTERS.pack(*(snapshot[name] for name in
                                       ("cr0", "cr2", "cr3", "cr4", "cr8", "efer", "apic-base")))
    return b"".join((*segments, gdt, idt, controls))


def read_protected_entry(mailbox, slots, long_mode, pvh, reset):
    record = mailbox[256:256 + SPECIAL_REGISTERS_SIZE]
    gdt_at = 8 * SEGMENT.size
    idt_at = gdt_at + DESCRIPTOR_TABLE.size
    control_at = idt_at + DESCRIPTOR_TABLE.size
    base, limit = DESCRIPTOR_TABLE.unpack_from(record, gdt_at)
    root = CONTROL_REGISTERS.unpack_from(record, control_at)[2]
    if limit != (31 if pvh else 23) or not slot_contains(slots, base, limit + 1):
        raise RuntimeError("protected entry GDT lies outside registered RAM")
    if long_mode and (root % PAGE_SIZE or not slot_contains(slots, root, PAGE_SIZE)):
        raise RuntimeError("long-mode page table root lies outside registered RAM")
    idt_base, idt_limit = DESCRIPTOR_TABLE.unpack_from(record, idt_at)
    if pvh and (idt_limit != 7 or not slot_contains(slots, idt_base, idt_limit + 1)):
        raise RuntimeError("PVH entry IDT lies outside registered RAM")
    code = SEGMENT.pack(0, 0xffffffff, 8, 11, 1, 0, not long_mode, 1, long_mode, 1, 0, 0)
    data = SEGMENT.pack(0, 0xffffffff, 16, 3, 1, 0, 1, 1, 0, 1, 0, 0)
    def expected(initial):
        profile = bytearray(initial)
        profile[:6 * SEGMENT.size] = code + data * 5
        DESCRIPTOR_TABLE.pack_into(profile, gdt_at, base, limit)
        controls = list(CONTROL_REGISTERS.unpack_from(initial, control_at))
        controls[0] |= 1
        if pvh:
            SEGMENT.pack_into(profile, 6 * SEGMENT.size, 0, 103, 24, 11, 1, 0, 0, 0, 0, 0, 0, 0)
            DESCRIPTOR_TABLE.pack_into(profile, idt_at, idt_base, idt_limit)
            controls[0] = 0x11
        if long_mode:
            controls[0] |= CR0_PAGING
            controls[2:4] = (root, CR4_PAE)
            controls[5] = EFER_LONG_MODE_ENABLE | EFER_LONG_MODE_ACTIVE
        CONTROL_REGISTERS.pack_into(profile, control_at, *controls)
        return profile
    if record not in (expected(reset), expected(bytes(SPECIAL_REGISTERS_SIZE))):
        raise RuntimeError("unsupported protected entry state")
    return record


def slot_contains(slots, address, size):
    return any(slot.gpa <= address and address + size <= slot.gpa + len(slot.offsets) * PAGE_SIZE for slot in slots)


def pack_msr_batch(entries):
    return MSR_HEADER.pack(len(entries), 0) + b"".join(
        MSR_ENTRY.pack(index, 0, value) for index, value in entries)


def unpack_msr_batch(record):
    count, reserved = MSR_HEADER.unpack_from(record)
    if reserved or count > MSR_BATCH_MAX or len(record) < MSR_HEADER.size + count * MSR_ENTRY.size:
        raise RuntimeError("invalid MSR batch")
    entries = []
    for offset in range(MSR_HEADER.size, MSR_HEADER.size + count * MSR_ENTRY.size, MSR_ENTRY.size):
        index, reserved, value = MSR_ENTRY.unpack_from(record, offset)
        if reserved:
            raise RuntimeError("reserved MSR entry field is nonzero")
        entries.append((index, value))
    return entries


def pack_cpuid(entries):
    return CPUID_HEADER.pack(len(entries), 0) + b"".join(CPUID_ENTRY.pack(*entry) for entry in entries)


def unpack_cpuid(record):
    count, reserved = CPUID_HEADER.unpack_from(record)
    if reserved or count > CPUID_MAX or len(record) < CPUID_HEADER.size + count * CPUID_ENTRY.size:
        raise RuntimeError("invalid CPUID table")
    return [CPUID_ENTRY.unpack_from(record, CPUID_HEADER.size + i * CPUID_ENTRY.size) for i in range(count)]


def cpuid_arguments(cpu, entries):
    return {"cpu-index": cpu, "entries": [
        dict(zip(CPUID_FIELDS, (*entry[:2], bool(entry[2]), *entry[3:]), strict=True)) for entry in entries
    ]}


def stop_process(process):
    if process.poll() is None:
        process.kill()
    process.wait()


class RunChannel:
    def __init__(self, connection, irq_fds=(), pulse_irq=None):
        self.connection = connection
        self.gsi_by_fd = {fd: gsi for gsi, fd in enumerate(irq_fds)}
        self.pulse_irq = pulse_irq
        self.irq_pulses = []
        self.exits = []
        self.interruptions = []
        self.timings = []
        try:
            self.connection.settimeout(3)
            if self.connection.recv(2) != b"R":
                raise RuntimeError("parent worker did not report readiness")
        except BaseException:
            self.connection.close()
            raise

    def read_exit(self):
        if self.connection.type != socket.SOCK_STREAM:
            return self.connection.recv(PIO_HEADER.size + PIO_BYTES + 1)
        data = bytearray()
        expected = 2
        while len(data) < expected:
            chunk = self.connection.recv(expected - len(data))
            if not chunk:
                break
            data.extend(chunk)
            if data[0] in (ord("M"), ord("Q")):
                expected = MMIO_WIRE.size
            elif data[0] in (ord("U"), ord("V")):
                expected = PIO_HEADER.size
                if len(data) >= expected:
                    operation, width, _, count = PIO_HEADER.unpack_from(data)
                    length = pio_size(width, count)
                    if operation == b"U":
                        expected += length
        return bytes(data)

    def dispatch_irqs(self, ready, running=False):
        pending = self.gsi_by_fd.keys() & set(ready)
        for fd in sorted(pending):
            os.eventfd_read(fd)
            gsi = self.gsi_by_fd[fd]
            self.pulse_irq(gsi)
            self.irq_pulses.append((gsi, running))
        return bool(pending)

    def run(self, request, cancellation, interrupt):
        started = time.monotonic()
        if select.select([self.connection], [], [], 0)[0]:
            raise RuntimeError("child replied before its next run request")
        if self.gsi_by_fd:
            self.dispatch_irqs(select.select(self.gsi_by_fd, [], [], 0)[0])
        self.connection.sendall(request)
        interrupted = False
        while True:
            timeout = max(0, cancellation.deadline - time.monotonic())
            ready, _, _ = select.select([self.connection, cancellation.descriptor, *self.gsi_by_fd], [], [], timeout)
            if self.connection in ready:
                if cancellation.descriptor in ready:
                    cancellation.applies()
                break
            if not ready:
                raise TimeoutError("parent worker did not stop after KVM_RUN")
            if cancellation.descriptor in ready and cancellation.applies() and not interrupted:
                interrupt()
                interrupted = True
            self.dispatch_irqs(ready, running=True)
        output = self.read_exit()
        if output == b"I\0" and interrupted:
            self.interruptions.append(round((time.monotonic() - started) * 1000, 3))
            return None
        if len(output) == 2 and output[0] == ord("O"):
            result = RunExit(KVM_EXIT_IO, IO_PORT, output[1:])
        elif len(output) >= PIO_HEADER.size and output[0] in (ord("U"), ord("V")):
            operation, width, port, count = PIO_HEADER.unpack_from(output)
            length = pio_size(width, count)
            is_write = operation == b"U"
            payload = output[PIO_HEADER.size:]
            if len(payload) != (length if is_write else 0):
                raise RuntimeError("invalid worker port I/O payload")
            result = RunExit(KVM_EXIT_IO, port, payload if is_write else bytes(length), is_write, count)
        elif len(output) == MMIO_WIRE.size and output[0] in (ord("M"), ord("Q")):
            operation, length, address, data = MMIO_WIRE.unpack(output)
            if length not in (1, 2, 4, 8):
                raise RuntimeError("invalid worker MMIO access width")
            result = RunExit(KVM_EXIT_MMIO, address, data[:length], operation == b"M")
        else:
            raise RuntimeError("parent worker did not return a recognized stopped exit")
        if result.reason == KVM_EXIT_IO and result.address == IO_PORT and result.is_write and result.width == 1:
            self.exits.extend(result.data)
        self.timings.append(round((time.monotonic() - started) * 1000, 3))
        return result

    def close(self):
        self.connection.close()


class RegisterChannel:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.cpu = None
        try:
            self.socket.settimeout(1)
            self.socket.connect(str(path))
            self.stream = self.socket.makefile("rb")
        except BaseException:
            self.socket.close()
            raise

    def exchange(self, command):
        payload = command.encode("ascii")
        checksum = f"{sum(payload) % 256:02x}".encode("ascii")
        self.socket.sendall(b"$" + payload + b"#" + checksum)
        if self.stream.read(2) != b"+$":
            raise RuntimeError("unexpected QEMU register reply header")
        payload = bytearray()
        for _ in range(4096):
            byte = self.stream.read(1)
            if byte == b"#":
                checksum = f"{sum(payload) % 256:02x}".encode("ascii")
                if self.stream.read(2) != checksum:
                    raise RuntimeError("invalid QEMU register reply checksum")
                self.socket.sendall(b"+")
                return bytes(payload)
            if not byte:
                break
            payload.extend(byte)
        raise RuntimeError("unterminated QEMU register reply")

    def read(self, index, size):
        value = self.exchange(f"p{index:x}")
        if len(value) != size * 2:
            raise RuntimeError(f"QEMU did not return a {size}-byte register for {index}")
        return int.from_bytes(bytes.fromhex(value.decode("ascii")), "little")

    def select_cpu(self, cpu):
        if self.cpu != cpu:
            if self.exchange(f"Hg{cpu + 1:x}") != b"OK":
                raise RuntimeError(f"QEMU rejected debugger vCPU {cpu}")
            self.cpu = cpu

    def write(self, index, size, value):
        encoded = value.to_bytes(size, "little").hex()
        if self.exchange(f"P{index:x}={encoded}") != b"OK":
            raise RuntimeError(f"QEMU rejected register {index}")

    def close(self):
        self.stream.close()
        self.socket.close()


class TcgChild:
    def __init__(self, qemu, output, socket_path, outer_ram, layouts, slots, cpu_count, mmio, pit_flags, irq_fds):
        self.process = None
        self.channel = None
        self.debugger = None
        self.special_monitor = None
        self.irqchip = bool(irq_fds)
        debugger_path = socket_path.with_name("registers.sock")
        self.special_monitor_path = socket_path.with_name("special-registers.sock")
        self.memory = outer_ram
        self.data_offset = slots[-1].offsets[-1] + 0x82
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, (output / "child.log").open("wb") as log:
                listener.bind(str(socket_path))
                listener.listen(1)
                listener.settimeout(3)
                exit_device = "isa-debugcon,iobase=0x30,chardev=port,run-control=on,forward-pio=on"
                if irq_fds:
                    exit_device += ",keep-pic-ports=on"
                if pit_flags is not None:
                    exit_device += ",keep-pit-ports=on"
                    if pit_flags & KVM_PIT_SPEAKER_DUMMY:
                        exit_device += ",keep-speaker-port=on"
                if mmio:
                    exit_device += f",mmio-base={MMIO_BASE}"
                pit = "off" if pit_flags is None else "on"
                command = [
                    qemu, *QEMU_OPTIONS, "-machine", f"pc,accel=tcg,pit={pit}", "-m", "16",
                    "-smp", str(cpu_count), "-serial", "none",
                    "-cpu", TCG_CHILD_CPU,
                    "-bios", output / "reset.rom", "-S", "-chardev", f"socket,id=port,path={socket_path}",
                    "-chardev", f"socket,id=regs,path={debugger_path},server=on,wait=off",
                    "-gdb", "chardev:regs",
                    "-qmp", f"unix:{self.special_monitor_path},server=on,wait=off",
                    "-device", exit_device,
                ]
                for slot, layout in zip(slots, layouts, strict=True):
                    command.extend(["-device", f"flexvm-shared-ram,id=slot{slot.identifier},"
                                    f"ram-fd={outer_ram},layout-fd={layout},addr={slot.gpa}"])
                self.process = subprocess.Popen(command, pass_fds=(outer_ram, *layouts), stdout=log, stderr=log)
                connection, _ = listener.accept()
                self.channel = RunChannel(connection, irq_fds, self.pulse_irq)
                self.debugger = RegisterChannel(debugger_path)
                description = self.debugger.exchange("qXfer:features:read:target.xml:0,fff")
                if b'<xi:include href="i386-64bit.xml"/>' not in description:
                    raise RuntimeError("unexpected QEMU register layout")
                for cpu in range(cpu_count):
                    self.debugger.select_cpu(cpu)
                    self.debugger.write(18, 4, 0)  # Real-mode code segment with zero base.
                    status, _ = self.mp_state(cpu, None if irq_fds else MP_RUNNABLE)
                    if status:
                        raise RuntimeError("TCG could not initialize the vCPU multiprocessing state")
        except BaseException:
            self.close()
            raise

    def run(self, cpu, cancellation, completion):
        if self.channel.timings and 0xa7 not in self.channel.exits and os.pread(self.memory, 1, self.data_offset) != b"\0":
            raise RuntimeError("child wrote its second result while stopped")
        request = b"D" + completion if completion else bytes((ord("R") + cpu,))
        return self.channel.run(request, cancellation, lambda: self.channel.connection.sendall(b"I"))

    def complete_read(self, cpu, completion):
        self.channel.connection.sendall(b"E" + completion)
        if self.channel.connection.recv(1) != b"E":
            raise RuntimeError("TCG worker did not acknowledge the completed read")

    def registers(self, cpu):
        self.debugger.select_cpu(cpu)
        registers = [0] * 18
        for peer_index, index, size in GDB_REGISTERS:
            registers[index] = self.debugger.read(peer_index, size)
        return REGISTERS.pack(*registers)

    def set_registers(self, cpu, record):
        self.debugger.select_cpu(cpu)
        registers = REGISTERS.unpack(record)
        for peer_index, index, size in GDB_REGISTERS:
            self.debugger.write(peer_index, size, registers[index])

    def special_command(self, operation, arguments=None):
        deadline = time.monotonic() + 3
        if self.special_monitor is None:
            self.special_monitor = HELPERS["QMP"](self.special_monitor_path, self.process, deadline)
        self.special_monitor.deadline = deadline
        return self.special_monitor.ask(operation, arguments)

    def special_registers(self, cpu):
        return pack_special_registers(self.special_command("x-flexvm-query-x86-sregs", {"cpu-index": cpu}))

    def set_protected_entry(self, cpu, record):
        table_at = 8 * SEGMENT.size
        base, limit = DESCRIPTOR_TABLE.unpack_from(record, table_at)
        controls = CONTROL_REGISTERS.unpack_from(record, table_at + 2 * DESCRIPTOR_TABLE.size)
        arguments = {"cpu-index": cpu, "gdt-base": base, "gdt-limit": limit}
        if controls[5] & EFER_LONG_MODE_ACTIVE:
            arguments["page-table-root"] = controls[2]
        if limit == 31:
            arguments["pvh-idt-base"] = DESCRIPTOR_TABLE.unpack_from(record, table_at + DESCRIPTOR_TABLE.size)[0]
        self.special_command("x-flexvm-set-x86-protected-entry", arguments)

    def floating_point(self, cpu):
        snapshot = self.special_command("x-flexvm-query-x86-fpu", {"cpu-index": cpu})
        record = bytes.fromhex(snapshot["record"])
        if len(record) != FPU_SIZE:
            raise RuntimeError("TCG parent worker did not return a floating-point record")
        return record

    def set_floating_point(self, cpu, record):
        self.special_command("x-flexvm-set-x86-fpu", {"cpu-index": cpu, "record": record.hex()})

    def lapic(self, cpu):
        return parse_lapic(self.special_command("x-flexvm-query-x86-lapic", {"cpu-index": cpu}))

    def set_lapic(self, cpu, record):
        self.special_command("x-flexvm-set-x86-lapic", {"cpu-index": cpu, "record": record.hex()})

    def access_msrs(self, cpu, entries, write):
        result = self.special_command("x-flexvm-access-x86-msrs", {
            "cpu-index": cpu, "write": write,
            "entries": [{"index": index, "value": value} for index, value in entries],
        })
        return [(entry["index"], entry["value"]) for entry in result["entries"]]

    def set_cpuid(self, cpu, entries):
        self.special_command("x-flexvm-set-x86-cpuid", cpuid_arguments(cpu, entries))

    def set_irq(self, gsi, level):
        self.special_command("x-flexvm-set-x86-gsi", {"gsi": gsi, "level": bool(level)})

    def irqchip(self, chip_id):
        snapshot = self.special_command("x-flexvm-access-x86-irqchip", {"chip-id": chip_id})
        return pack_irqchip(chip_id, snapshot)

    def set_irqchip(self, chip_id, record):
        payload = record[IRQCHIP_HEADER.size:IRQCHIP_HEADER.size + IRQCHIP_PAYLOAD_SIZES[chip_id]]
        self.special_command("x-flexvm-access-x86-irqchip", {"chip-id": chip_id, "record": payload.hex()})

    def pit_state(self):
        return parse_pit_state(self.special_command("x-flexvm-access-x86-pit", {}))

    def set_pit_state(self, record):
        self.special_command("x-flexvm-access-x86-pit", {"record": record.hex()})

    def debugregs(self, cpu):
        result = self.special_command("x-flexvm-access-x86-debugregs", {"cpu-index": cpu})
        return pack_debugregs(result)

    def set_debugregs(self, cpu, record):
        state = dict(zip(DEBUGREGS_FIELDS, DEBUGREGS.unpack(record), strict=True))
        self.special_command("x-flexvm-access-x86-debugregs", {"cpu-index": cpu, "state": state})

    def mp_state(self, cpu, state=None):
        args = {"cpu-index": cpu}
        if state is not None:
            args["state"] = state
        result = self.special_command("x-flexvm-access-x86-mp-state", args)
        return result["status"], result["state"]

    def xcrs(self, cpu):
        state = self.special_command("x-flexvm-access-x86-xcr0", {"cpu-index": cpu})
        return pack_xcrs(state["value"])

    def set_xcrs(self, cpu, record):
        count, flags, index, reserved, value = XCRS.unpack(record)
        if (count, flags, index, reserved) != (1, 0, 0, 0):
            raise RuntimeError("invalid canonical XCR state")
        state = self.special_command("x-flexvm-access-x86-xcr0", {"cpu-index": cpu, "value": value})
        return state["status"]

    def xsave(self, cpu):
        state = self.special_command("x-flexvm-access-x86-xsave", {"cpu-index": cpu})
        return 0, parse_xsave(state)

    def set_xsave(self, cpu, record):
        state = self.special_command("x-flexvm-access-x86-xsave", {"cpu-index": cpu, "record": record.hex()})
        return state["status"]

    def vcpu_events(self, cpu, record=None):
        args = {"cpu-index": cpu, "irqchip": self.irqchip}
        if record is not None:
            args["record"] = record.hex()
        state = self.special_command("x-flexvm-access-x86-vcpu-events", args)
        return parse_vcpu_events(state)

    def pulse_irq(self, gsi):
        self.special_command("x-flexvm-pulse-x86-gsi", {"gsi": gsi})

    def close(self):
        try:
            if self.special_monitor is not None:
                self.special_monitor.close()
                self.special_monitor = None
            if self.debugger is not None:
                self.debugger.close()
                self.debugger = None
        finally:
            if self.channel is not None:
                self.channel.close()
            if self.process is not None:
                stop_process(self.process)
                self.process = None


class KvmChild:
    def __init__(self, output, outer_ram, layouts, slots, cpu_count, irqchip, pit_flags, irq_fds, tss_gpa):
        self.process = None
        self.channel = None
        self.sigqueue = ctypes.CDLL(None, use_errno=True).sigqueue
        self.sigqueue.argtypes = (ctypes.c_int, ctypes.c_int, SignalValue)
        self.sigqueue.restype = ctypes.c_int
        connection, worker = socket.socketpair(type=socket.SOCK_SEQPACKET)
        try:
            with worker, (output / "child.log").open("wb") as log:
                control = worker.fileno()
                pit_request = 0 if pit_flags is None else pit_flags + 1
                tss_request = 0xffffffff if tss_gpa is None else tss_gpa
                command = [output / "native-worker", str(control), str(outer_ram), str(cpu_count),
                           str(int(irqchip)), str(pit_request), str(tss_request), *map(str, irq_fds)]
                for slot, layout in zip(slots, layouts, strict=True):
                    command.extend(map(str, (layout, slot.gpa, slot.identifier)))
                self.process = subprocess.Popen(command, pass_fds=(control, outer_ram, *irq_fds, *layouts),
                                                stdout=log, stderr=log)
            self.channel = RunChannel(connection)
        except BaseException:
            connection.close()
            self.close()
            raise

    def run(self, cpu, cancellation, completion):
        sequence = cancellation.sequence
        if not 0 < sequence < 1 << 31:
            raise RuntimeError("invalid native cancellation sequence")
        return self.channel.run(struct.pack("<cBI", b"R", cpu, sequence) + completion, cancellation,
                                lambda: self.interrupt(sequence))

    def complete_read(self, cpu, completion):
        self.channel.connection.sendall(bytes((ord("E"), cpu)) + completion)
        if self.channel.connection.recv(2) != b"E":
            raise RuntimeError("native worker did not acknowledge the completed read")

    def interrupt(self, sequence):
        if self.sigqueue(self.process.pid, signal.SIGRTMIN, SignalValue(integer=sequence)):
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))

    def registers(self, cpu):
        self.channel.connection.sendall(bytes((ord("G"), cpu)))
        registers = self.channel.connection.recv(REGISTERS.size + 1)
        if len(registers) != REGISTERS.size:
            raise RuntimeError("native parent worker did not return a register record")
        return registers

    def set_registers(self, cpu, record):
        self.channel.connection.sendall(bytes((ord("S"), cpu)) + record)
        if self.channel.connection.recv(2) != b"S":
            raise RuntimeError("native parent worker did not acknowledge the register write")

    def special_registers(self, cpu):
        self.channel.connection.sendall(bytes((ord("X"), cpu)))
        registers = self.channel.connection.recv(SPECIAL_REGISTERS_SIZE + 1)
        if len(registers) != SPECIAL_REGISTERS_SIZE:
            raise RuntimeError("native parent worker did not return a special register record")
        return registers

    def set_protected_entry(self, cpu, record):
        self.channel.connection.sendall(bytes((ord("P"), cpu)) + record)
        if self.channel.connection.recv(2) != b"P":
            raise RuntimeError("native parent worker did not acknowledge protected entry")

    def floating_point(self, cpu):
        self.channel.connection.sendall(bytes((ord("F"), cpu)))
        record = self.channel.connection.recv(FPU_SIZE + 1)
        if len(record) != FPU_SIZE:
            raise RuntimeError("native parent worker did not return a floating-point record")
        return record

    def set_floating_point(self, cpu, record):
        self.channel.connection.sendall(bytes((ord("W"), cpu)) + record)
        if self.channel.connection.recv(2) != b"W":
            raise RuntimeError("native parent worker did not acknowledge the floating-point write")

    def lapic(self, cpu):
        self.channel.connection.sendall(bytes((ord("A"), cpu)))
        record = self.channel.connection.recv(LAPIC_SIZE + 1)
        if len(record) != LAPIC_SIZE:
            raise RuntimeError("native parent worker returned an invalid LAPIC image")
        return record

    def set_lapic(self, cpu, record):
        self.channel.connection.sendall(bytes((ord("B"), cpu)) + record)
        if self.channel.connection.recv(2) != b"B":
            raise RuntimeError("native parent worker did not acknowledge the LAPIC write")

    def access_msrs(self, cpu, entries, write):
        payload = pack_msr_batch(entries)
        self.channel.connection.sendall(bytes((ord("N" if write else "M"), cpu)) + payload)
        maximum = MSR_HEADER.size if write else len(payload)
        result = self.channel.connection.recv(maximum + 1)
        if len(result) < MSR_HEADER.size or len(result) > maximum:
            raise RuntimeError("native parent worker returned an invalid MSR result size")
        count, reserved = MSR_HEADER.unpack_from(result)
        if reserved or count > len(entries) or len(result) != MSR_HEADER.size + (0 if write else count * MSR_ENTRY.size):
            raise RuntimeError("native parent worker returned an invalid MSR result")
        return entries[:count] if write else unpack_msr_batch(result)

    def set_cpuid(self, cpu, entries):
        self.channel.connection.sendall(bytes((ord("C"), cpu)) + pack_cpuid(entries))
        if self.channel.connection.recv(2) != b"C":
            raise RuntimeError("native parent worker did not acknowledge the CPUID table")

    def set_irq(self, gsi, level):
        self.channel.connection.sendall(b"L\0" + IRQ_RECORD.pack(gsi, level))
        if self.channel.connection.recv(2) != b"L":
            raise RuntimeError("native parent worker did not acknowledge the IRQ line")

    def irqchip(self, chip_id):
        record = IRQCHIP_HEADER.pack(chip_id, 0).ljust(IRQCHIP_SIZE, b"\0")
        self.channel.connection.sendall(b"J\0" + record)
        result = self.channel.connection.recv(IRQCHIP_SIZE + 1)
        if len(result) != IRQCHIP_SIZE or IRQCHIP_HEADER.unpack_from(result)[0] != chip_id:
            raise RuntimeError("native parent worker returned an invalid irqchip image")
        return result

    def set_irqchip(self, chip_id, record):
        self.channel.connection.sendall(b"K\0" + record)
        if self.channel.connection.recv(2) != b"K":
            raise RuntimeError("native parent worker did not acknowledge the irqchip write")

    def pit_state(self):
        self.channel.connection.sendall(b"T\0")
        result = self.channel.connection.recv(PIT_STATE_SIZE + 1)
        if len(result) != PIT_STATE_SIZE:
            raise RuntimeError("native parent worker returned an invalid PIT image")
        return result

    def set_pit_state(self, record):
        self.channel.connection.sendall(b"Y\0" + record)
        if self.channel.connection.recv(2) != b"Y":
            raise RuntimeError("native parent worker did not acknowledge the PIT write")

    def debugregs(self, cpu):
        self.channel.connection.sendall(bytes((ord("H"), cpu)))
        result = self.channel.connection.recv(DEBUGREGS.size + 1)
        if len(result) != DEBUGREGS.size:
            raise RuntimeError("native parent worker returned an invalid debug register image")
        return result

    def set_debugregs(self, cpu, record):
        self.channel.connection.sendall(bytes((ord("I"), cpu)) + record)
        if self.channel.connection.recv(2) != b"I":
            raise RuntimeError("native parent worker did not acknowledge the debug registers")

    def mp_state(self, cpu, state=None):
        if state is None:
            request = bytes((ord("p"), cpu))
        else:
            request = bytes((ord("q"), cpu)) + MP_STATE.pack(state)
        self.channel.connection.sendall(request)
        result = self.channel.connection.recv(MP_STATE_REPLY.size + 1)
        if len(result) != MP_STATE_REPLY.size:
            raise RuntimeError("native parent worker returned an invalid MP state")
        return MP_STATE_REPLY.unpack(result)

    def xcrs(self, cpu):
        self.channel.connection.sendall(bytes((ord("s"), cpu)))
        result = self.channel.connection.recv(XCRS.size + 1)
        if len(result) != XCRS.size:
            raise RuntimeError("native parent worker returned an invalid XCR image")
        return result

    def set_xcrs(self, cpu, record):
        self.channel.connection.sendall(bytes((ord("t"), cpu)) + record)
        result = self.channel.connection.recv(IOCTL_RESULT.size + 1)
        if len(result) != IOCTL_RESULT.size:
            raise RuntimeError("native parent worker returned an invalid XCR write result")
        return IOCTL_RESULT.unpack(result)[0]

    def xsave(self, cpu):
        self.channel.connection.sendall(bytes((ord("u"), cpu)))
        result = self.channel.connection.recv(IOCTL_RESULT.size + XSAVE_SIZE + 1)
        if len(result) != IOCTL_RESULT.size + XSAVE_SIZE:
            raise RuntimeError("native parent worker returned an invalid XSAVE image")
        return IOCTL_RESULT.unpack_from(result)[0], result[IOCTL_RESULT.size:]

    def set_xsave(self, cpu, record):
        self.channel.connection.sendall(bytes((ord("v"), cpu)) + record)
        result = self.channel.connection.recv(IOCTL_RESULT.size + 1)
        if len(result) != IOCTL_RESULT.size:
            raise RuntimeError("native parent worker returned an invalid XSAVE write result")
        return IOCTL_RESULT.unpack(result)[0]

    def vcpu_events(self, cpu, record=None):
        request = bytes((ord("e" if record is None else "f"), cpu))
        self.channel.connection.sendall(request + (record if record is not None else b""))
        result = self.channel.connection.recv(IOCTL_RESULT.size + VCPU_EVENTS_SIZE + 1)
        if len(result) != IOCTL_RESULT.size + VCPU_EVENTS_SIZE:
            raise RuntimeError("native parent worker returned an invalid vCPU event result")
        return IOCTL_RESULT.unpack_from(result)[0], result[IOCTL_RESULT.size:]

    def close(self):
        if self.channel is not None:
            self.channel.close()
        if self.process is not None:
            try:
                return self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                stop_process(self.process)
                return self.process.returncode
            finally:
                self.process = None
        return None


def doorbell_peer(server, memory, requests, cancellations, irq_fds, replies):
    peer, _ = server.accept()
    try:
        peer.settimeout(3)
        # ivshmem protocol 0. The parent is peer 0 and the outer guest is peer 1.
        peer.sendall(struct.pack("<qq", 0, 1))
        for value, descriptor in ((-1, memory), (0, requests), (0, cancellations),
                                  *((0, fd) for fd in irq_fds), (1, replies)):
            if socket.send_fds(peer, [struct.pack("<q", value)], [descriptor]) != 8:
                raise RuntimeError("short ivshmem setup message")
        return peer
    except BaseException:
        peer.close()
        raise


def read_tcg_cpuid(monitor):
    def query(requests):
        rows = [(function, index, flag, 0, 0, 0, 0) for function, index, flag in requests]
        result = monitor.ask("x-flexvm-query-x86-cpuid", cpuid_arguments(0, rows))
        found = [tuple(entry[field] for field in CPUID_FIELDS) for entry in result["entries"]]
        if [entry[:3] for entry in found] != requests:
            raise RuntimeError("TCG CPUID query returned a different function or subleaf")
        return found

    roots = [0, 0x40000000, 0x80000000]
    maxima = query([(function, 0, 0) for function in roots])
    indexed = (4, 7, 0xb, 0xd, 0x1f, 0x8000001d)
    basic = []
    for first, result in zip(roots, maxima, strict=True):
        maximum = result[3]
        if first <= maximum <= first + 0x3f:
            basic.extend((function, 0, int(function in indexed)) for function in range(first, maximum + 1))
    entries = query(basic)
    for function, _, significant, eax, _, _, edx in tuple(entries):
        if not significant:
            continue
        if function == 7:
            if eax >= 32:
                raise RuntimeError("TCG structured feature list exceeds the fixture budget")
            entries.extend(query([(function, index, 1) for index in range(1, eax + 1)]))
        elif function == 0xd and (eax or edx):
            xsave = (edx << 32) | eax
            entries.extend(query([(function, index, 1) for index in range(1, 64) if index == 1 or xsave & (1 << index)]))
        elif function in (4, 0xb, 0x1f, 0x8000001d):
            for index in range(1, 16):
                entry, = query([(function, index, 1)])
                entries.append(entry)
                if (function in (4, 0x8000001d) and not entry[3] & 0x1f or
                        function in (0xb, 0x1f) and not entry[4] & 0xffff):
                    break
    return sorted(entries)


@contextmanager
def model_monitor(qemu, output, control, cpu_count, name):
    path = control / f"{name}.sock"
    with (output / f"{name}-model.log").open("ab") as log:
        process = subprocess.Popen([
            qemu, *QEMU_OPTIONS, "-machine", "pc,accel=tcg", "-cpu", TCG_CHILD_CPU,
            "-m", "16", "-smp", str(cpu_count), "-serial", "none", "-S",
            "-qmp", f"unix:{path},server=on,wait=off",
        ], stdout=log, stderr=log)
    try:
        monitor = HELPERS["QMP"](path, process, time.monotonic() + 3)
        try:
            yield monitor
        finally:
            monitor.close()
    finally:
        stop_process(process)
        path.unlink(missing_ok=True)


def model_cpuid(engine, qemu, output, control, cpu_count):
    if engine == "kvm":
        native = subprocess.run([output / "native-worker", "--supported-cpuid"], capture_output=True, timeout=3)
        if native.returncode:
            raise RuntimeError(f"native CPUID query failed: {native.stderr.decode(errors='replace')}")
        entries = [entry for entry in unpack_cpuid(native.stdout) if not entry[2] & ~1]
    else:
        with model_monitor(qemu, output, control, cpu_count, "cpuid") as monitor:
            entries = read_tcg_cpuid(monitor)
    if not 0 < len(entries) <= CPUID_MAX:
        raise RuntimeError("CPUID model returned an empty or oversized profile")
    return entries


def parse_lapic(value):
    record = bytes.fromhex(value["record"])
    if len(record) != LAPIC_SIZE:
        raise RuntimeError("TCG parent worker returned an invalid LAPIC image")
    return record


def reset_lapic(engine, qemu, output, control, cpu_count, cpu):
    if engine == "kvm":
        native = subprocess.run([output / "native-worker", "--reset-lapic", str(cpu)], capture_output=True, timeout=3)
        if native.returncode or len(native.stdout) != LAPIC_SIZE:
            raise RuntimeError(f"native reset LAPIC query failed: {native.stderr.decode(errors='replace')}")
        return native.stdout
    with model_monitor(qemu, output, control, cpu_count, "lapic") as monitor:
        return parse_lapic(monitor.ask("x-flexvm-query-x86-lapic", {"cpu-index": cpu}))


def reset_sregs(engine, qemu, output, control, cpu_count, cpu, irqchip):
    if engine == "kvm":
        native = subprocess.run([output / "native-worker", "--reset-sregs", str(cpu), str(int(irqchip))],
                                capture_output=True, timeout=3)
        if native.returncode or len(native.stdout) != SPECIAL_REGISTERS_SIZE:
            raise RuntimeError(f"native reset SREGS query failed: {native.stderr.decode(errors='replace')}")
        return native.stdout
    with model_monitor(qemu, output, control, cpu_count, "sregs") as monitor:
        return pack_special_registers(monitor.ask("x-flexvm-query-x86-sregs", {"cpu-index": cpu}))


def pack_irqchip(chip_id, snapshot):
    payload = bytes.fromhex(snapshot["record"])
    if len(payload) != IRQCHIP_PAYLOAD_SIZES[chip_id]:
        raise RuntimeError("TCG parent worker returned an invalid irqchip image")
    return (IRQCHIP_HEADER.pack(chip_id, 0) + payload).ljust(IRQCHIP_SIZE, b"\0")


def reset_irqchips(engine, qemu, output, control, cpu_count):
    count = len(IRQCHIP_PAYLOAD_SIZES)
    if engine == "kvm":
        native = subprocess.run([output / "native-worker", "--reset-irqchips"], capture_output=True, timeout=3)
        if native.returncode or len(native.stdout) != count * IRQCHIP_SIZE:
            raise RuntimeError(f"native reset irqchip query failed: {native.stderr.decode(errors='replace')}")
        return [native.stdout[id * IRQCHIP_SIZE:(id + 1) * IRQCHIP_SIZE] for id in range(count)]
    with model_monitor(qemu, output, control, cpu_count, "irqchips") as monitor:
        return [pack_irqchip(id, monitor.ask("x-flexvm-access-x86-irqchip", {"chip-id": id}))
                for id in range(count)]


def parse_pit_state(snapshot):
    record = bytes.fromhex(snapshot["record"])
    if len(record) != PIT_STATE_SIZE:
        raise RuntimeError("TCG parent worker returned an invalid PIT image")
    return record


def unstarted_pit_state(engine, qemu, output, control, flags, staged):
    if engine == "kvm":
        option = "--reset-pit" if staged is None else "--staged-pit"
        native = subprocess.run([output / "native-worker", option, str(flags)], input=staged,
                                capture_output=True, timeout=3)
        if native.returncode or len(native.stdout) != PIT_STATE_SIZE:
            raise RuntimeError(f"native unstarted PIT query failed: {native.stderr.decode(errors='replace')}")
        return native.stdout
    with model_monitor(qemu, output, control, 1, "pit") as monitor:
        args = {} if staged is None else {"record": staged.hex()}
        return parse_pit_state(monitor.ask("x-flexvm-access-x86-pit", args))


def pack_debugregs(state):
    return DEBUGREGS.pack(*(state[field] for field in DEBUGREGS_FIELDS))


def reset_debugregs(engine, qemu, output, control, cpu_count, cpu):
    if engine == "kvm":
        native = subprocess.run([output / "native-worker", "--reset-debugregs", str(cpu)],
                                capture_output=True, timeout=3)
        if native.returncode or len(native.stdout) != DEBUGREGS.size:
            raise RuntimeError(f"native debug register query failed: {native.stderr.decode(errors='replace')}")
        return native.stdout
    with model_monitor(qemu, output, control, cpu_count, "debugregs") as monitor:
        return pack_debugregs(monitor.ask("x-flexvm-access-x86-debugregs", {"cpu-index": cpu}))


def unstarted_mp_state(engine, qemu, output, control, cpu_count, cpu, irqchip, staged):
    if engine == "kvm":
        command = [output / "native-worker", "--reset-mp", str(cpu), str(int(irqchip)), *map(str, staged)]
        native = subprocess.run(command, capture_output=True, timeout=3)
        if native.returncode or len(native.stdout) != MP_STATE.size:
            raise RuntimeError(f"native MP state query failed: {native.stderr.decode(errors='replace')}")
        return MP_STATE.unpack(native.stdout)[0]
    with model_monitor(qemu, output, control, cpu_count, "mp-state") as monitor:
        args = {"cpu-index": cpu}
        for initial in staged if irqchip else (MP_RUNNABLE,):
            result = monitor.ask("x-flexvm-access-x86-mp-state", {**args, "state": initial})
            if result["status"]:
                raise RuntimeError("TCG rejected a staged MP state")
        return monitor.ask("x-flexvm-access-x86-mp-state", args)["state"]


def pack_xcrs(xcr0):
    return XCRS.pack(1, 0, 0, 0, xcr0)


def reset_xcrs(engine, qemu, output, control, cpu_count, cpu):
    if engine == "kvm":
        native = subprocess.run([output / "native-worker", "--reset-xcrs", str(cpu)],
                                capture_output=True, timeout=3)
        if native.returncode or len(native.stdout) != XCRS.size:
            raise RuntimeError(f"native XCR query failed: {native.stderr.decode(errors='replace')}")
        return native.stdout
    with model_monitor(qemu, output, control, cpu_count, "xcrs") as monitor:
        return pack_xcrs(monitor.ask("x-flexvm-access-x86-xcr0", {"cpu-index": cpu})["value"])


def parse_xsave(state):
    record = bytes.fromhex(state["record"])
    if state["status"] or len(record) != XSAVE_SIZE:
        raise RuntimeError("TCG parent worker returned an invalid XSAVE image")
    return record


def reset_xsave(engine, qemu, output, control, cpu_count, cpu):
    if engine == "kvm":
        native = subprocess.run([output / "native-worker", "--reset-xsave", str(cpu)],
                                capture_output=True, timeout=3)
        if native.returncode or len(native.stdout) != XSAVE_SIZE:
            raise RuntimeError(f"native XSAVE query failed: {native.stderr.decode(errors='replace')}")
        return native.stdout
    with model_monitor(qemu, output, control, cpu_count, "xsave") as monitor:
        return parse_xsave(monitor.ask("x-flexvm-access-x86-xsave", {"cpu-index": cpu}))


def parse_vcpu_events(state):
    record = bytes.fromhex(state["record"])
    if len(record) != VCPU_EVENTS_SIZE:
        raise RuntimeError("TCG parent worker returned an invalid vCPU event image")
    return state["status"], record


def reset_vcpu_events(engine, qemu, output, control, cpu_count, cpu, irqchip):
    if engine == "kvm":
        native = subprocess.run([output / "native-worker", "--reset-events", str(cpu), str(int(irqchip))],
                                capture_output=True, timeout=3)
        if native.returncode or len(native.stdout) != VCPU_EVENTS_SIZE:
            raise RuntimeError(f"native event query failed: {native.stderr.decode(errors='replace')}")
        return native.stdout
    with model_monitor(qemu, output, control, cpu_count, "vcpu-events") as monitor:
        status, record = parse_vcpu_events(monitor.ask("x-flexvm-access-x86-vcpu-events",
                                                       {"cpu-index": cpu, "irqchip": irqchip}))
        if status:
            raise RuntimeError("TCG rejected an unstarted vCPU event query")
        return record


def merge_vcpu_events(previous, record):
    if previous is None:
        return record
    initial, = struct.unpack_from("<I", previous, VCPU_EVENT_FLAGS)
    flags, = struct.unpack_from("<I", record, VCPU_EVENT_FLAGS)
    result = bytearray(record)
    optional_fields = ((EVENT_NMI_PENDING, 13, 14), (EVENT_SIPI_VECTOR, 16, 20),
                       (EVENT_SHADOW, 11, 12), (EVENT_SMM, 24, 28))
    for flag, start, end in optional_fields:
        if initial & flag and not flags & flag:
            result[start:end] = previous[start:end]
    struct.pack_into("<I", result, VCPU_EVENT_FLAGS, flags | initial)
    return bytes(result)


def staged_smm_active(record):
    flags, = struct.unpack_from("<I", record, VCPU_EVENT_FLAGS)
    return bool(flags & EVENT_SMM and (record[24] or record[25]))


def read_slot_table(mailbox, ram_pages, outer_bytes, protected_entry, split_slot, zero_slot):
    first_gpa = PROTECTED_GPA if protected_entry else PAGE_SIZE
    if zero_slot:
        first_gpa = 0
    expected = [(0, ram_pages, first_gpa)]
    if split_slot:
        first_pages = ram_pages // 2
        expected = [(0, first_pages, first_gpa), (5, ram_pages - first_pages, SPLIT_GPA)]
    count, = struct.unpack_from("<I", mailbox, 32)
    if count != len(expected) or count > MAX_SLOTS:
        raise RuntimeError("unexpected number of registered RAM slots")
    slots = []
    used_offsets = set()
    offset_position = RAM_ADDRESS_AT
    for index, record in enumerate(expected):
        identifier, pages, gpa = struct.unpack_from("<IIQ", mailbox, 640 + index * 16)
        if (identifier, pages, gpa) != record:
            raise RuntimeError("unexpected guest physical slot layout")
        offsets = struct.unpack_from(f"<{pages}Q", mailbox, offset_position)
        offset_position += 8 * pages
        for offset in offsets:
            if (offset % PAGE_SIZE or not MIB <= offset <= outer_bytes - PAGE_SIZE or
                    offset in used_offsets):
                raise RuntimeError("registered slot page is outside outer RAM or repeated")
            used_offsets.add(offset)
        slots.append(SlotLayout(identifier, gpa, offsets))
    return slots


def start_child(engine, qemu, output, control, outer_ram, slots, cpu_count, mmio, irqchip, pit_flags, irq_fds, tss_gpa):
    if not irqchip:
        irq_fds = ()
    if tss_gpa is not None and any(slot.gpa < tss_gpa + 3 * PAGE_SIZE and
                                  tss_gpa < slot.gpa + len(slot.offsets) * PAGE_SIZE for slot in slots):
        raise RuntimeError("TSS overlaps registered guest RAM")
    with ExitStack() as manifests:
        layouts = []
        for slot in slots:
            manifest = os.memfd_create("flexvm-slot-layout", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            manifests.callback(os.close, manifest)
            layout = struct.pack(f"<{len(slot.offsets)}Q", *slot.offsets)
            if os.write(manifest, layout) != len(layout):
                raise RuntimeError("short write of the RAM slot layout")
            fcntl.fcntl(manifest, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL)
            layouts.append(manifest)
        if engine == "kvm":
            return KvmChild(output, outer_ram, layouts, slots, cpu_count, irqchip, pit_flags, irq_fds, tss_gpa)
        return TcgChild(qemu, output, control / "child.sock", outer_ram, layouts, slots, cpu_count, mmio,
                        pit_flags, irq_fds)


def verify_slot_spans(pid, slots):
    mappings = {}
    extents = 0
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or fields[5] != "/memfd:flexvm-outer-ram (deleted)":
            continue
        if fields[1] != "rw-s":
            raise RuntimeError("parent worker RAM is not a writable shared mapping")
        start, end = (int(address, 16) for address in fields[0].split("-"))
        offset = int(fields[2], 16)
        for delta in range(0, end - start, PAGE_SIZE):
            if offset + delta in mappings:
                raise RuntimeError("parent worker RAM maps the same page twice")
            mappings[offset + delta] = start + delta
        extents += 1
    if len(mappings) != sum(len(slot.offsets) for slot in slots):
        raise RuntimeError("parent worker mapped the wrong number of pages")
    for slot in slots:
        start = mappings.get(slot.offsets[0], -1)
        if start < 0 or any(mappings.get(offset) != start + index * PAGE_SIZE
                            for index, offset in enumerate(slot.offsets)):
            raise RuntimeError(f"parent worker RAM does not match slot {slot.identifier}")
    return extents


def exercise(qemu, kernel, output, reject_close, parent_engine, ram_pages, protected_entry,
             split_slot, interrupt_run, cpu_count, long_mode, fpu, msrs, cpuid, mmio, mmio_read,
             ioeventfd, irqchip, pit, irqfd, zero_slot, tss, lapic, pio, complete_read, pio_boundary, pvh,
             irqchip_state, pit_state, debugregs, mp_state, xcrs, xsave, vcpu_events):
    reset = bytearray(64 << 10)
    reset[0xfff0] = 0xf4  # Halt if register setup did not select the client's code.
    (output / "reset.rom").write_bytes(reset)
    expected_interruptions = TEST_INTERRUPTS if interrupt_run else 0
    expected = [OPEN_VM]
    if tss:
        expected.append(SET_TSS_ADDR)
    if irqchip:
        expected.append(CREATE_IRQCHIP)
        if pit:
            expected.append(CREATE_PIT)
        if pit_state:
            expected.extend((GET_PIT, SET_PIT, GET_PIT))
        if irqchip_state:
            expected.extend((GET_IRQCHIP, GET_IRQCHIP, GET_IRQCHIP, SET_IRQCHIP))
        expected.append(SET_IRQ_LINE)
    elif pvh:
        expected.append(CREATE_IRQCHIP)
    expected.extend((OPEN_CPU, GET_SREGS) * cpu_count)
    if debugregs:
        expected.extend((GET_DEBUGREGS, SET_DEBUGREGS, GET_DEBUGREGS))
    if mp_state:
        expected.extend((GET_MP_STATE, SET_MP_STATE, GET_MP_STATE, SET_MP_STATE, GET_MP_STATE))
    if xcrs:
        expected.extend((GET_XCRS, SET_XCRS, GET_XCRS))
    if xsave:
        expected.extend((SET_XCRS, GET_XSAVE, SET_XSAVE, GET_XSAVE, SET_XSAVE))
    if vcpu_events:
        expected.extend((GET_VCPU_EVENTS, SET_VCPU_EVENTS, SET_VCPU_EVENTS, GET_VCPU_EVENTS))
    if lapic:
        expected.append(GET_LAPIC)
    expected_counters = []
    expected_mmio = MMIO_WRITES if mmio else ()
    if ioeventfd:
        expected.append(RUN)
        expected_mmio += (MMIO_WRITES[0],)
    if mmio:
        expected.extend([RUN] * len(expected_mmio))
    if mmio_read:
        for i in range(len(MMIO_READS)):
            expected.extend((RUN, GET_REGS))
            expected_counters.append(0)
            if i == 0 and complete_read:
                expected.extend((COMPLETE_READ, GET_REGS))
                expected_counters.append(0)
    expected.extend((RUN, GET_REGS, GET_SREGS))
    if cpuid:
        expected.insert(0, GET_SUPPORTED_CPUID)
    expected_counters.append(0x1357)
    expected_io = [(0, 0xcc)] if ioeventfd else []
    expected_io.append((0, 0x42))
    if cpu_count == 2:
        expected.extend((RUN, GET_REGS, GET_REGS, CLOSE_CPU))
        expected_counters.extend((0x3344, 0x1357))
        expected_io.append((1, 0x56))
    if fpu:
        expected.extend((GET_FPU, SET_FPU))
    if msrs:
        expected.extend((GET_MSRS, SET_MSRS))
    if lapic:
        expected.extend((GET_LAPIC, SET_LAPIC, GET_LAPIC))
    if irqchip_state:
        expected.extend((GET_IRQCHIP, GET_IRQCHIP, GET_IRQCHIP, SET_IRQCHIP, GET_IRQCHIP, SET_IRQCHIP))
    if vcpu_events:
        expected.extend((SET_REGS, GET_VCPU_EVENTS, SET_VCPU_EVENTS, RUN, GET_REGS, GET_VCPU_EVENTS,
                         SET_VCPU_EVENTS, GET_VCPU_EVENTS, RUN, GET_REGS, GET_VCPU_EVENTS,
                         SET_VCPU_EVENTS, RUN, GET_REGS, GET_VCPU_EVENTS))
        expected_counters.extend((0x7a41,) * 3)
        expected_io.extend(((0, 0x8b),) * 3)
    if irqchip:
        expected.append(SET_IRQ_LINE)
    expected.extend((SET_REGS, GET_REGS, *((RUN, GET_REGS) * expected_interruptions), RUN, GET_REGS))
    if fpu:
        expected.append(GET_FPU)
    if msrs:
        expected.append(GET_MSRS)
    if lapic:
        expected.append(GET_LAPIC)
    if irqchip:
        expected.append(SET_IRQ_LINE)
    expected_counters.extend((*([0x3579] * (1 + expected_interruptions)), 0x2468))
    expected_io.append((0, 0xa7))
    if irqchip_state:
        expected.extend((SET_IRQ_LINE, SET_REGS, RUN, GET_REGS, SET_IRQ_LINE))
        expected_counters.append(0x6543)
        expected_io.append((0, 0x7c))
    if pit:
        expected.extend((SET_REGS, RUN))
        if pit_state:
            expected.extend((GET_PIT, SET_PIT, GET_PIT, RUN))
            expected_io.append((0, 0x5b))
        expected.append(GET_REGS)
        expected_counters.append(0x4321)
        expected_io.append((0, 0x5c))
    if irqfd:
        expected.extend((SET_REGS, RUN, GET_REGS) * 2)
        expected_counters.extend((0x5432, 0x5432))
        expected_io.extend(((0, 0x6c), (0, 0x6c)))
    if mp_state:
        expected.extend((SET_REGS, *((SET_MP_STATE, GET_MP_STATE) * 4), RUN, GET_REGS, GET_MP_STATE,
                         SET_MP_STATE, GET_MP_STATE, GET_REGS))
        expected_counters.extend((0x7e01, 0x7e01))
        expected_io.append((0, 0x7e))
    if debugregs:
        expected.extend((SET_REGS, RUN, GET_REGS, GET_DEBUGREGS, SET_DEBUGREGS, GET_DEBUGREGS))
        expected_counters.append(0x7654)
        expected_io.append((0, 0x7d))
    if xcrs:
        expected.extend((SET_REGS, RUN, GET_REGS, GET_XCRS, SET_XCRS, GET_XCRS, RUN, GET_REGS))
        expected_counters.extend((0x7a11, 0x7a11))
        expected_io.extend(((0, 0x7f), (0, 0x7f)))
    if xsave:
        expected.extend((SET_REGS, RUN, GET_REGS, GET_XSAVE, SET_XSAVE, RUN, GET_REGS))
        expected_counters.extend((0x7a31, 0x7a31))
        expected_io.extend(((0, 0x8a), (0, 0x8a)))
    if vcpu_events:
        expected.extend((SET_VCPU_EVENTS, GET_VCPU_EVENTS, SET_VCPU_EVENTS, SET_MP_STATE, GET_MP_STATE, GET_SREGS))
    expected.extend((CLOSE_CPU, CLOSE_VM))
    if reject_close:
        expected = expected[:-1]
    observed = []
    counters = []
    io_events = []
    mmio_events = []
    completed_reads = []
    pio_writes = []
    pio_reads = []
    expected_pio_writes = (PIO_WRITES if pio else ()) + (PIO_BOUNDARY_WRITES if pio_boundary else ())
    expected_pio_reads = (PIO_READS if pio else ()) + (PIO_BOUNDARY_READS if pio_boundary else ())
    pio_exit_limit = sum(len(data) // width for _, width, data in (*expected_pio_writes, *expected_pio_reads))
    pending_read = None
    irqchip_created = False
    pit_flags = None
    staged_pit = None
    staged_debugregs = {}
    staged_mp_states = {}
    staged_xcrs = {}
    staged_xsave = {}
    staged_vcpu_events = {}
    baseline_vcpu_events = {}
    tss_gpa = None
    irq_levels = []
    expected_irq_levels = IRQ_LEVELS + ([(6, 1), (6, 0)] if irqchip_state else []) if irqchip else []
    staged_irq_levels = []
    staged_irqchips = {}
    reset_irqchip_images = None
    open_cpus = set()
    started_cpus = set()
    reset_registers = {}
    special = None
    supported_cpuid = []
    child = None
    slot_size = ram_pages * PAGE_SIZE
    outer_mib = max(192, (slot_size + MIB - 1) // MIB + 128)
    outer_ram_size = outer_mib * MIB
    with ExitStack() as cleanup:
        control = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="flexvm-kvm-")))
        server = cleanup.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        server.bind(str(control / "doorbell"))
        server.listen(1)
        server.settimeout(3)
        memory = os.memfd_create("flexvm-kvm-mailbox", os.MFD_CLOEXEC)
        cleanup.callback(os.close, memory)
        os.ftruncate(memory, MAILBOX_SIZE)
        mapping = cleanup.enter_context(mmap.mmap(memory, MAILBOX_SIZE))
        struct.pack_into("<II", mapping, 0, 0x4d564b46, 34)
        outer_ram = os.memfd_create("flexvm-outer-ram", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        cleanup.callback(os.close, outer_ram)
        os.ftruncate(outer_ram, outer_ram_size)
        fcntl.fcntl(outer_ram, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        requests = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
        cleanup.callback(os.close, requests)
        cancellations = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
        cleanup.callback(os.close, cancellations)
        replies = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
        cleanup.callback(os.close, replies)
        irq_fds = []
        for _ in range(GSI_COUNT):
            fd = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
            cleanup.callback(os.close, fd)
            irq_fds.append(fd)
        command = [
            qemu, *QEMU_OPTIONS, "-machine", "q35,accel=tcg,memory-backend=outer-ram",
            "-cpu", "max,vmx=off,svm=off", "-m", str(outer_mib), "-smp", "1",
            "-object", f"memory-backend-file,id=outer-ram,mem-path=/proc/self/fd/{outer_ram},share=on,size={outer_mib}M",
            "-serial", "stdio", "-kernel", kernel, "-initrd", output / "initramfs",
            "-append", "console=ttyS0 loglevel=5 panic=1 rdinit=/init",
            "-chardev", f"socket,id=doorbell,path={control / 'doorbell'}",
            "-device", f"ivshmem-doorbell,chardev=doorbell,vectors={2 + len(irq_fds)}",
        ]
        with (output / "outer.log").open("wb") as log:
            outer = subprocess.Popen(command, pass_fds=(outer_ram,), stdout=log, stderr=log)
        cleanup.callback(stop_process, outer)
        cleanup.enter_context(doorbell_peer(server, memory, requests, cancellations, irq_fds, replies))
        exited = os.pidfd_open(outer.pid)
        cleanup.callback(os.close, exited)
        deadline = time.monotonic() + 60
        while True:
            descriptors = [exited, requests, cancellations]
            if child is not None and child.process is not None:
                descriptors.extend(child.channel.gsi_by_fd)
            readable, _, _ = select.select(descriptors, [], [], max(0, deadline - time.monotonic()))
            if exited in readable:
                break
            if cancellations in readable and requests not in readable:
                # The ordinary I/O exit can win a race with the cancel doorbell.
                os.eventfd_read(cancellations)
                complete, = struct.unpack_from("<I", mapping, 12)
                cancelled, = struct.unpack_from("<I", mapping, 40)
                if cancelled > complete:
                    raise RuntimeError("cancellation has no live run")
                continue
            if child is not None and child.channel.dispatch_irqs(readable) and requests not in readable:
                continue
            if requests not in readable:
                raise TimeoutError("outer guest did not shut down")
            if os.eventfd_read(requests) != 1:
                raise RuntimeError("multiple outstanding doorbell requests")
            pending, complete, opcode, _, length = struct.unpack_from("<IIIII", mapping, 8)
            if pending != complete + 1 or len(observed) >= len(expected) or opcode != expected[len(observed)]:
                raise RuntimeError(f"unexpected doorbell request {pending}, command {opcode}")
            cpu, = struct.unpack_from("<I", mapping, 44)
            cpu_commands = (CLOSE_CPU, RUN, GET_REGS, GET_SREGS, SET_REGS, GET_FPU, SET_FPU, GET_MSRS, SET_MSRS,
                            GET_LAPIC, SET_LAPIC, COMPLETE_READ, GET_DEBUGREGS, SET_DEBUGREGS,
                            GET_MP_STATE, SET_MP_STATE, GET_XCRS, SET_XCRS, GET_XSAVE, SET_XSAVE,
                            GET_VCPU_EVENTS, SET_VCPU_EVENTS)
            if opcode in cpu_commands and cpu not in open_cpus:
                raise RuntimeError(f"command {opcode} requested unopened vCPU {cpu}")
            status = 0
            if opcode == GET_SUPPORTED_CPUID:
                if length:
                    raise RuntimeError("unexpected memory argument for CPUID query")
                supported_cpuid = model_cpuid(parent_engine, qemu, output, control, cpu_count)
                record = pack_cpuid(supported_cpuid)
                mapping[CPUID_AT:CPUID_AT + len(record)] = record
            elif opcode == SET_TSS_ADDR:
                address, = struct.unpack_from("<I", mapping, TSS_AT)
                if length or child is not None or address != FIRECRACKER_TSS_GPA:
                    raise RuntimeError("invalid Firecracker TSS address")
                tss_gpa = address
            elif opcode == CREATE_IRQCHIP:
                if length or irqchip_created:
                    raise RuntimeError("invalid irqchip creation request")
                irqchip_created = True
            elif opcode == CREATE_PIT:
                flags, = struct.unpack_from("<I", mapping, PIT_FLAGS_AT)
                if length or not irqchip_created or pit_flags is not None or flags & ~KVM_PIT_SPEAKER_DUMMY:
                    raise RuntimeError("invalid PIT creation request")
                pit_flags = flags
            elif opcode in (GET_PIT, SET_PIT):
                if length or pit_flags is None:
                    raise RuntimeError("PIT state requires an initialized timer")
                if opcode == GET_PIT:
                    record = (child.pit_state() if child is not None else
                              unstarted_pit_state(parent_engine, qemu, output, control, pit_flags, staged_pit))
                    mapping[PIT_STATE_AT:PIT_STATE_AT + PIT_STATE_SIZE] = record
                else:
                    record = mapping[PIT_STATE_AT:PIT_STATE_AT + PIT_STATE_SIZE]
                    if child is None:
                        staged_pit = record
                    else:
                        child.set_pit_state(record)
            elif opcode in (GET_IRQCHIP, SET_IRQCHIP):
                record = mapping[IRQCHIP_AT:IRQCHIP_AT + IRQCHIP_SIZE]
                id = IRQCHIP_HEADER.unpack_from(record)[0]
                if length or not irqchip_created or id >= len(IRQCHIP_PAYLOAD_SIZES):
                    raise RuntimeError("invalid irqchip state request")
                if opcode == SET_IRQCHIP:
                    if child is None:
                        staged_irqchips[id] = record
                    else:
                        child.set_irqchip(id, record)
                else:
                    if child is not None:
                        image = child.irqchip(id)
                    elif id in staged_irqchips:
                        image = staged_irqchips[id]
                    else:
                        if reset_irqchip_images is None:
                            reset_irqchip_images = reset_irqchips(parent_engine, qemu, output, control, cpu_count)
                        image = reset_irqchip_images[id]
                    mapping[IRQCHIP_AT:IRQCHIP_AT + IRQCHIP_SIZE] = image
            elif opcode == SET_IRQ_LINE:
                line, level = IRQ_RECORD.unpack_from(mapping, IRQ_AT)
                if length or not irqchip_created or line >= GSI_COUNT or level > 1:
                    raise RuntimeError("invalid irqchip line request")
                irq_levels.append((line, level))
                if child is None:
                    staged_irq_levels.append((line, level))
                else:
                    child.set_irq(line, level)
            elif opcode == OPEN_CPU:
                if length or cpu >= cpu_count or cpu in open_cpus:
                    raise RuntimeError(f"invalid request to create vCPU {cpu}")
                open_cpus.add(cpu)
            elif opcode == GET_LAPIC:
                if length or not irqchip_created:
                    raise RuntimeError("LAPIC read requires an irqchip")
                record = (reset_lapic(parent_engine, qemu, output, control, cpu_count, cpu)
                          if child is None else child.lapic(cpu))
                mapping[LAPIC_AT:LAPIC_AT + LAPIC_SIZE] = record
            elif opcode == GET_SREGS and cpu not in started_cpus:
                if length:
                    raise RuntimeError("unexpected memory argument for reset SREGS")
                registers = reset_sregs(parent_engine, qemu, output, control, cpu_count, cpu, irqchip_created)
                reset_registers[cpu] = registers
                mapping[64:64 + SPECIAL_REGISTERS_SIZE] = registers
            elif opcode == SET_LAPIC:
                if length or not irqchip_created or cpu not in started_cpus:
                    raise RuntimeError("LAPIC write requires a stopped, initialized vCPU")
                child.set_lapic(cpu, mapping[LAPIC_AT:LAPIC_AT + LAPIC_SIZE])
            elif opcode == COMPLETE_READ:
                if length or pending_read is None:
                    raise RuntimeError("completion-only entry requires an outstanding read")
                child.complete_read(cpu, read_completion(mapping, pending_read, pio_reads, completed_reads))
                pending_read = None
            elif opcode in (GET_DEBUGREGS, SET_DEBUGREGS):
                if length:
                    raise RuntimeError("unexpected memory argument for debug registers")
                end = DEBUGREGS_AT + DEBUGREGS.size
                if opcode == SET_DEBUGREGS:
                    record = mapping[DEBUGREGS_AT:end]
                    if child is None:
                        staged_debugregs[cpu] = record
                    else:
                        child.set_debugregs(cpu, record)
                else:
                    if child is not None:
                        record = child.debugregs(cpu)
                    elif cpu in staged_debugregs:
                        record = staged_debugregs[cpu]
                    else:
                        record = reset_debugregs(parent_engine, qemu, output, control, cpu_count, cpu)
                    mapping[DEBUGREGS_AT:end] = record
            elif opcode in (GET_MP_STATE, SET_MP_STATE):
                if length:
                    raise RuntimeError("unexpected memory argument for MP state")
                if opcode == SET_MP_STATE:
                    state, = MP_STATE.unpack_from(mapping, MP_STATE_AT)
                    if child is None:
                        previous = staged_mp_states.get(cpu, ())
                        # Preserve the pending SIPI across subsequent MP state writes.
                        retain_sipi = state != MP_SIPI_RECEIVED and MP_SIPI_RECEIVED in previous
                        events = staged_vcpu_events.get(cpu)
                        if state in (MP_INIT_RECEIVED, MP_SIPI_RECEIVED) and events and staged_smm_active(events):
                            status = -errno.EINVAL
                        else:
                            staged_mp_states[cpu] = (MP_SIPI_RECEIVED, state) if retain_sipi else (state,)
                    else:
                        status, _ = child.mp_state(cpu, state)
                else:
                    if child is None:
                        state = unstarted_mp_state(parent_engine, qemu, output, control, cpu_count,
                                                   cpu, irqchip_created, staged_mp_states.get(cpu, ()))
                        if cpu in staged_mp_states:
                            staged_mp_states[cpu] = (state,)
                    else:
                        status, state = child.mp_state(cpu)
                    if not status:
                        MP_STATE.pack_into(mapping, MP_STATE_AT, state)
            elif opcode in (GET_XCRS, SET_XCRS):
                if length:
                    raise RuntimeError("unexpected memory argument for XCRs")
                end = XCRS_AT + XCRS.size
                if opcode == SET_XCRS:
                    record = mapping[XCRS_AT:end]
                    if cpu in started_cpus:
                        status = child.set_xcrs(cpu, record)
                    else:
                        staged_xcrs[cpu] = record
                else:
                    if cpu in started_cpus:
                        record = child.xcrs(cpu)
                    elif cpu in staged_xcrs:
                        record = staged_xcrs[cpu]
                    else:
                        record = reset_xcrs(parent_engine, qemu, output, control, cpu_count, cpu)
                    mapping[XCRS_AT:end] = record
            elif opcode in (GET_XSAVE, SET_XSAVE):
                if length:
                    raise RuntimeError("unexpected memory argument for XSAVE")
                end = XSAVE_AT + XSAVE_SIZE
                if opcode == SET_XSAVE:
                    record = mapping[XSAVE_AT:end]
                    if cpu in started_cpus:
                        status = child.set_xsave(cpu, record)
                    else:
                        staged_xsave[cpu] = record
                else:
                    if cpu in started_cpus:
                        status, record = child.xsave(cpu)
                    elif cpu in staged_xsave:
                        record = staged_xsave[cpu]
                    else:
                        record = reset_xsave(parent_engine, qemu, output, control, cpu_count, cpu)
                    if not status:
                        mapping[XSAVE_AT:end] = record
            elif opcode in (GET_VCPU_EVENTS, SET_VCPU_EVENTS):
                if length:
                    raise RuntimeError("unexpected memory argument for vCPU events")
                end = VCPU_EVENTS_AT + VCPU_EVENTS_SIZE
                if opcode == SET_VCPU_EVENTS:
                    record = mapping[VCPU_EVENTS_AT:end]
                    if child is None:
                        state = staged_mp_states.get(cpu, (MP_RUNNABLE,))[-1]
                        if state in (MP_INIT_RECEIVED, MP_SIPI_RECEIVED) and staged_smm_active(record):
                            status = -errno.EINVAL
                        else:
                            staged_vcpu_events[cpu] = merge_vcpu_events(staged_vcpu_events.get(cpu), record)
                    else:
                        status, _ = child.vcpu_events(cpu, record)
                else:
                    if child is None:
                        if cpu not in baseline_vcpu_events:
                            baseline_vcpu_events[cpu] = reset_vcpu_events(parent_engine, qemu, output, control,
                                                                        cpu_count, cpu, irqchip_created)
                        record = baseline_vcpu_events[cpu]
                        if cpu in staged_vcpu_events:
                            record = bytearray(merge_vcpu_events(record, staged_vcpu_events[cpu]))
                            if record[1] in (3, 4):
                                record[0] = 0
                            if record[10]:
                                record[8] = record[10] = 0
                            struct.pack_into("<II", record, 16, 0, EVENT_NMI_PENDING | EVENT_SHADOW | EVENT_SMM)
                    else:
                        status, record = child.vcpu_events(cpu)
                    if not status:
                        mapping[VCPU_EVENTS_AT:end] = record
            elif opcode == RUN:
                if child is None:
                    if length != slot_size or len(open_cpus) != cpu_count:
                        raise RuntimeError("unexpected total size of registered RAM")
                    slots = read_slot_table(mapping, ram_pages, outer_ram_size, protected_entry, split_slot, zero_slot)
                    child = start_child(parent_engine, qemu, output, control, outer_ram, slots,
                                        cpu_count, mmio, irqchip_created, pit_flags, irq_fds, tss_gpa)
                    cleanup.callback(child.close)
                    extents = verify_slot_spans(child.process.pid, slots)
                    for id, image in staged_irqchips.items():
                        child.set_irqchip(id, image)
                    if staged_pit is not None:
                        child.set_pit_state(staged_pit)
                    for id, events in staged_vcpu_events.items():
                        status, _ = child.vcpu_events(id, events)
                        if status:
                            raise RuntimeError(f"parent worker rejected staged vCPU events with error {status}")
                    for id, record in staged_debugregs.items():
                        child.set_debugregs(id, record)
                    for id, states in staged_mp_states.items():
                        for state in states:
                            status, _ = child.mp_state(id, state)
                            if status:
                                raise RuntimeError(f"parent worker rejected staged MP state with error {status}")
                    for line, level in staged_irq_levels:
                        child.set_irq(line, level)
                elif length:
                    raise RuntimeError("unexpected slot registration after the first run")
                if cpu not in started_cpus:
                    cpuid_valid, = struct.unpack_from("<I", mapping, CPUID_VALID_AT)
                    if cpuid_valid != int(cpuid):
                        raise RuntimeError("unexpected staged CPUID table")
                    if cpuid_valid:
                        child.set_cpuid(cpu, unpack_cpuid(mapping[CPUID_AT:CPUID_AT + CPUID_BYTES]))
                    if cpu in staged_xcrs:
                        xcr_status = child.set_xcrs(cpu, staged_xcrs.pop(cpu))
                        if xcr_status:
                            raise RuntimeError(f"parent worker rejected staged XCRs with error {xcr_status}")
                    if cpu in staged_xsave:
                        xsave_status = child.set_xsave(cpu, staged_xsave.pop(cpu))
                        if xsave_status:
                            raise RuntimeError(f"parent worker rejected staged XSAVE with error {xsave_status}")
                    if protected_entry:
                        state = read_protected_entry(mapping, slots, long_mode, pvh, reset_registers[cpu])
                        child.set_protected_entry(cpu, state)
                    child.set_registers(cpu, mapping[64:64 + REGISTERS.size])
                    fpu_valid, = struct.unpack_from("<I", mapping, FPU_VALID_AT)
                    if fpu_valid != int(fpu):
                        raise RuntimeError("unexpected staged floating-point state")
                    if fpu_valid:
                        child.set_floating_point(cpu, mapping[FPU_AT:FPU_AT + FPU_SIZE])
                    initial_msrs = unpack_msr_batch(mapping[MSR_AT:MSR_AT + MSR_HEADER.size + MSR_ENTRY.size * MSR_BATCH_MAX])
                    if bool(initial_msrs) != msrs:
                        raise RuntimeError("unexpected staged boot MSR state")
                    if initial_msrs and child.access_msrs(cpu, initial_msrs, True) != initial_msrs:
                        raise RuntimeError("worker rejected staged boot MSR state")
                    lapic_valid, = struct.unpack_from("<I", mapping, LAPIC_VALID_AT)
                    if lapic_valid != int(lapic):
                        raise RuntimeError("unexpected staged LAPIC image")
                    if lapic_valid:
                        child.set_lapic(cpu, mapping[LAPIC_AT:LAPIC_AT + LAPIC_SIZE])
                    started_cpus.add(cpu)
                completion = read_completion(mapping, pending_read, pio_reads, completed_reads)
                pending_read = None
                try:
                    result = child.run(cpu, RunCancellation(cancellations, mapping, pending, deadline), completion)
                except TimeoutError as error:
                    raise TimeoutError(f"KVM_RUN {pending} stopped responding; PIO writes={pio_writes}, "
                                       f"PIO reads={pio_reads}, last port values={io_events}") from error
                if result is None:
                    status = -errno.EINTR
                else:
                    if result.reason == KVM_EXIT_IO:
                        if result.is_write and result.address == IO_PORT and result.width == 1 and result.count == 1:
                            io_events.append((cpu, result.data[0]))
                        elif not pio:
                            raise RuntimeError("unexpected port I/O exit")
                        else:
                            if io_events or len(pio_writes) + len(pio_reads) >= pio_exit_limit:
                                raise RuntimeError("unexpected port I/O after the fixture prelude")
                            # A REP instruction may complete through one or several exits.
                            expected.insert(len(observed), RUN)
                            if result.is_write:
                                pio_writes.append((result.address, result.width, result.data))
                            else:
                                pending_read = result
                                if complete_read and result.address == 0x3fd:
                                    at = len(observed) + 1
                                    expected[at:at] = (COMPLETE_READ, GET_REGS)
                                    expected_counters.insert(len(counters), 0)
                        if result.is_write:
                            mapping[PIO_DATA_AT:PIO_DATA_AT + len(result.data)] = result.data
                    elif result.is_write:
                        mmio_events.append((result.address, result.data))
                    else:
                        if not mmio_read or cpu_count != 1:
                            raise RuntimeError("unexpected MMIO read")
                        pending_read = result
                    mapping[EXIT_AT:EXIT_AT + EXIT_RECORD.size] = result.record()
            elif length:
                raise RuntimeError(f"unexpected memory argument for command {opcode}")
            elif opcode == GET_REGS:
                registers = child.registers(cpu)
                mapping[64:64 + REGISTERS.size] = registers
                counters.append(REGISTERS.unpack(registers)[2])
            elif opcode == SET_REGS:
                child.set_registers(cpu, mapping[64:64 + REGISTERS.size])
            elif opcode == GET_SREGS:
                registers = child.special_registers(cpu)
                mapping[64:64 + SPECIAL_REGISTERS_SIZE] = registers
                special = {
                    "cs_selector": SEGMENT.unpack_from(registers)[2],
                    "cs_long": bool(SEGMENT.unpack_from(registers)[8]),
                    "ds_base": SEGMENT.unpack_from(registers, SEGMENT.size)[0],
                    "gdt_base": DESCRIPTOR_TABLE.unpack_from(registers, 8 * SEGMENT.size)[0],
                    "idt_base": DESCRIPTOR_TABLE.unpack_from(registers, 8 * SEGMENT.size + DESCRIPTOR_TABLE.size)[0],
                    "tr_selector": SEGMENT.unpack_from(registers, 6 * SEGMENT.size)[2],
                }
                control_state = CONTROL_REGISTERS.unpack_from(registers, 8 * SEGMENT.size + 2 * DESCRIPTOR_TABLE.size)
                special.update(cr0=control_state[0], cr2=control_state[1], cr3=control_state[2],
                               cr4=control_state[3], efer=control_state[5])
            elif opcode == GET_FPU:
                mapping[FPU_AT:FPU_AT + FPU_SIZE] = child.floating_point(cpu)
            elif opcode == SET_FPU:
                child.set_floating_point(cpu, mapping[FPU_AT:FPU_AT + FPU_SIZE])
            elif opcode in (GET_MSRS, SET_MSRS):
                entries = unpack_msr_batch(mapping[MSR_AT:MSR_AT + MSR_HEADER.size + MSR_ENTRY.size * MSR_BATCH_MAX])
                completed = child.access_msrs(cpu, entries, opcode == SET_MSRS)
                if [index for index, _ in completed] != [index for index, _ in entries[:len(completed)]]:
                    raise RuntimeError("worker returned a different MSR prefix")
                record = pack_msr_batch(completed)
                mapping[MSR_AT:MSR_AT + len(record)] = record
            elif opcode == CLOSE_CPU:
                open_cpus.remove(cpu)
                staged_mp_states.pop(cpu, None)
                staged_xcrs.pop(cpu, None)
                staged_xsave.pop(cpu, None)
                staged_vcpu_events.pop(cpu, None)
                baseline_vcpu_events.pop(cpu, None)
                if not open_cpus:
                    # The guest can unpin its pages after the last CPU closes.
                    if reject_close:
                        status = -errno.EIO
                    else:
                        result = child.close()
                        if parent_engine == "kvm" and result != 0:
                            raise RuntimeError(f"native parent worker shut down with status {result}")
            observed.append(opcode)
            struct.pack_into("<i", mapping, 20, status)
            struct.pack_into("<I", mapping, 12, pending)
            os.eventfd_write(replies, 1)
        guest = (output / "outer.log").read_text(errors="replace")
        if (outer.wait() != 0 or observed != expected or child is None or io_events != expected_io
                or tuple(mmio_events) != expected_mmio
                or coalesce_pio(pio_writes) != expected_pio_writes or coalesce_pio(pio_reads) != expected_pio_reads
                or pending_read is not None or tuple(completed_reads) != (MMIO_READS if mmio_read else ())
                or irq_levels != expected_irq_levels
                or pit_flags != (KVM_PIT_SPEAKER_DUMMY if pit else None)
                or len(child.channel.interruptions) != expected_interruptions or counters != expected_counters
                or interrupt_run and "PASS stopped and resumed the same running child" not in guest
                or cpu_count == 2 and "PASS two vCPUs kept independent state in one child" not in guest
                or long_mode and "PASS x86-64 child used guest page tables and a virtual RAM alias" not in guest
                or fpu and "PASS x87 and XMM state reached the parent worker" not in guest
                or msrs and "PASS x86 boot MSRs reached the parent worker" not in guest
                or cpuid and "PASS child CPUID instructions used the installed vCPU profiles" not in guest
                or mmio and "PASS MMIO writes returned physical addresses and exact data" not in guest
                or mmio_read and "PASS MMIO reads continued with VMM-supplied bytes" not in guest
                or ioeventfd and "PASS KVM_IOEVENTFD signaled matched MMIO and PIO writes" not in guest
                or irqchip and "PASS child PIC delivered and acknowledged the parent IRQ" not in guest
                or pit and "PASS PIT woke the halted vCPU" not in guest
                or pit_state and "PASS restored live PIT state woke the halted vCPU" not in guest
                or debugregs and "PASS staged hardware breakpoint and live debug registers" not in guest
                or mp_state and "PASS real IRQ woke a vCPU restored to KVM_MP_STATE_HALTED" not in guest
                or xcrs and "PASS guest XGETBV and XSETBV used the actual parent XCR0" not in guest
                or xsave and "PASS XSAVE installed and read actual x87, MXCSR and AVX state" not in guest
                or vcpu_events and "PASS real x86 exception, NMI, IRQ and nonzero startup vector" not in guest
                or irqfd and "PASS KVM_IRQFD woke an active run and honored deassignment and pending signals" not in guest
                or zero_slot and "PASS zero-based RAM shared every tested page across the legacy PC region" not in guest
                or tss and "PASS child ran with Firecracker's three-page TSS reservation" not in guest
                or lapic and "PASS VMM and guest updated the parent LAPIC" not in guest
                or pio and "PASS x86 port I/O preserved widths, counts, and VMM read data" not in guest
                or complete_read and "PASS interrupted KVM_RUN completed one input without executing the following instruction" not in guest
                or pio_boundary and "PASS x86 port I/O kept the original width across device boundaries" not in guest
                or pvh and "PASS PVH entry executed with Firecracker's descriptor and control state" not in guest
                or irqchip_state and "PASS VMM-configured IOAPIC routed a real interrupt to the guest" not in guest
                or "PASS /dev/kvm returned two port I/O exits" not in guest
                or "PASS parent KVM guest shutdown" not in guest):
            raise RuntimeError(f"parent execution proof failed; commands={observed}, see outer.log")
        pulses = child.channel.irq_pulses
        if irqfd and parent_engine == "tcg":
            if len(pulses) != 2 or pulses[0] != (3, True) or pulses[1][0] != 3:
                raise RuntimeError(f"unexpected TCG interrupt doorbells: {pulses}")
        elif mp_state and parent_engine == "tcg":
            if pulses != [(3, True)]:
                raise RuntimeError(f"unexpected MP state wakeup IRQ: {pulses}")
        elif pulses:
            raise RuntimeError(f"unexpected TCG interrupt doorbells: {pulses}")
        retained = "retaining registered RAM until the enclosing VM exits" in guest
        if retained != reject_close:
            raise RuntimeError("unexpected guest RAM pin disposition")
        if reject_close and (child.process is None or child.process.poll() is not None):
            raise RuntimeError("rejected close did not retain the child until enclosing cleanup")
    if ram_pages <= MAX_REAL_MODE_PAGES:
        layout_summary = {"outer_page_offsets": [offset for slot in slots for offset in slot.offsets]}
    else:
        layout_summary = {"sample_outer_page_offsets": [(slot.offsets[0], slot.offsets[-1]) for slot in slots]}
    return {
        "guest_path": "/dev/kvm", "guest_vmx": False, "guest_svm": False,
        "boot_mode": "long" if long_mode else "protected" if protected_entry else "real", "slot_gpa": slots[0].gpa,
        "guest_slots": [{"id": slot.identifier, "gpa": slot.gpa, "pages": len(slot.offsets)} for slot in slots],
        "parent_accelerator": parent_engine, "parent_commands": observed, "transport": "eventfd and MSI-X",
        "io_values": child.channel.exits, "child_memory_write_visible": True, "same_child_worker": True,
        "vcpu_io_events": io_events, "vcpu_count": cpu_count,
        "floating_point": fpu,
        "boot_msrs": msrs,
        "configured_cpuid": cpuid,
        "supported_cpuid_entries": len(supported_cpuid),
        "mmio_writes": [{"address": address, "data": data.hex()} for address, data in mmio_events],
        "mmio_reads": [{"address": address, "data": data.hex()} for address, data in completed_reads],
        "ioeventfd": ioeventfd,
        "irq_levels": irq_levels,
        "irqchip_state": irqchip_state,
        "pit_flags": pit_flags,
        "pit_state": pit_state,
        "debugregs": debugregs,
        "mp_state": mp_state,
        "xcrs": xcrs,
        "xsave": xsave,
        "vcpu_events": vcpu_events,
        "irqfd": irqfd,
        "tcg_irqfd_pulses": pulses,
        "zero_based_ram": zero_slot,
        "tss_gpa": tss_gpa,
        "lapic": lapic,
        "completed_read_without_entry": complete_read,
        "pio_boundary": pio_boundary,
        "pvh": pvh,
        "pio_writes": [{"port": port, "width": width, "data": data.hex()} for port, width, data in pio_writes],
        "pio_reads": [{"port": port, "width": width, "data": data.hex()} for port, width, data in pio_reads],
        "register_counters": counters,
        "interrupted_runs": len(child.channel.interruptions),
        "interrupted_run_ms": child.channel.interruptions,
        "special_registers": special,
        "page_alias": True, "mapped_page_bytes": slot_size, "mapped_page_count": ram_pages,
        "outer_memory_bytes": outer_ram_size, **layout_summary,
        "mapped_extents": extents,
        "worker_stopped_before_close_reply": not reject_close, "page_retained_on_rejected_close": retained,
        "client_run_ns": client_timings(guest), "worker_run_ms": child.channel.timings, "worker_control": "direct socket",
    }


def client_timings(log):
    match = re.search(r"KVM_RUN_NS first=(\d+) warm=(\d+)", log)
    if match is None:
        raise RuntimeError("missing client run timing")
    return {"first": int(match[1]), "warm": int(match[2])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--kernel-build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-oracle", action="store_true")
    parser.add_argument("--parent-engine", choices=("tcg", "kvm"), default="tcg")
    parser.add_argument("--ram-pages", type=int, default=2, help=f"number of pages from 1 to {MAX_SLOT_PAGES}")
    parser.add_argument("--protected-entry", action="store_true", help="execute a 32-bit child above 16 MiB")
    parser.add_argument("--split-slot", action="store_true", help="divide memory between two discontiguous GPAs")
    parser.add_argument("--interrupt-run", action="store_true", help="interrupt live child execution before resuming")
    parser.add_argument("--two-vcpus", action="store_true", help="run two vCPUs serially with shared child RAM")
    parser.add_argument("--long-mode", action="store_true", help="enter x86-64 mode with client-supplied page tables")
    parser.add_argument("--fpu", action="store_true", help="exercise x87 and XMM state in long mode")
    parser.add_argument("--msrs", action="store_true", help="exercise x86 Linux boot MSRs in long mode")
    parser.add_argument("--cpuid", action="store_true", help="query and install x86 CPUID profiles")
    parser.add_argument("--mmio-write", action="store_true", help="return physical MMIO write exits in long mode")
    parser.add_argument("--mmio-read", action="store_true", help="complete physical MMIO reads after the write exits")
    parser.add_argument("--ioeventfd", action="store_true", help="signal guest eventfds for MMIO and port writes")
    parser.add_argument("--irqchip", action="store_true", help="deliver a real PIC interrupt on a stopped worker")
    parser.add_argument("--pit", action="store_true", help="program a PIT interrupt that wakes a halted worker")
    parser.add_argument("--pit-state", action="store_true", help="restore timer state and verify a real wakeup")
    parser.add_argument("--debugregs", action="store_true", help="verify staged debug registers and a hardware breakpoint")
    parser.add_argument("--mp-state", action="store_true", help="restore a halted vCPU and wake it through an IRQ")
    parser.add_argument("--xcrs", action="store_true", help="verify real XGETBV and XSETBV with VMM-restored XCR0")
    parser.add_argument("--xsave", action="store_true", help="verify real x87, MXCSR and AVX state restore")
    parser.add_argument("--vcpu-events", action="store_true", help="restore real x86 exception, IRQ and NMI state")
    parser.add_argument("--irqfd", action="store_true", help="wake an active run through KVM_IRQFD")
    parser.add_argument("--zero-slot", action="store_true", help="share RAM at GPA zero across the PC legacy region")
    parser.add_argument("--tss", action="store_true", help="reserve Firecracker's x86 TSS address")
    parser.add_argument("--lapic", action="store_true", help="get and set parent-owned xAPIC state")
    parser.add_argument("--pio", action="store_true", help="exercise arbitrary x86 port reads and writes")
    parser.add_argument("--complete-read", action="store_true", help="complete a read before an immediate exit")
    parser.add_argument("--pio-boundary", action="store_true", help="preserve the port and width across device boundaries")
    parser.add_argument("--pvh", action="store_true", help="install Firecracker's x86 PVH bootstrap state")
    parser.add_argument("--irqchip-state", action="store_true", help="read and install PIC and IOAPIC state")
    parser.add_argument("--reject-close", action="store_true", help="verify page retention when the parent refuses close")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.mmio_read or args.ioeventfd:
        args.mmio_write = True
    if args.pio_boundary:
        args.pio = args.irqchip = True
    if args.pvh:
        args.zero_slot = args.protected_entry = True
        if args.ram_pages < 8192:
            parser.error("--pvh needs at least 8192 pages for the kernel entry point")
    if args.pit_state:
        args.pit = True
    if args.xcrs or args.xsave:
        args.cpuid = True
    if args.pit or args.irqfd or args.tss or args.lapic or args.irqchip_state or args.mp_state or args.vcpu_events:
        args.irqchip = True
    if args.vcpu_events and (args.pit or args.irqfd or args.irqchip_state or args.mp_state):
        parser.error("--vcpu-events uses its own PIC interrupt fixture")
    if args.mp_state and (args.pit or args.irqfd or args.irqchip_state):
        parser.error("--mp-state uses its own PIC interrupt fixture")
    if args.pit and args.irqfd:
        parser.error("--pit and --irqfd use separate fixtures")
    if args.irqchip_state and (args.pit or args.irqfd):
        parser.error("--irqchip-state uses a separate interrupt fixture from --pit and --irqfd")
    if args.fpu and not args.long_mode:
        parser.error("--fpu requires long mode")
    if args.msrs and (not args.long_mode or args.fpu):
        parser.error("--msrs requires long mode and a separate run from --fpu")
    if args.long_mode:
        if args.two_vcpus or args.ram_pages < (8 if args.split_slot else 4):
            parser.error("--long-mode requires one vCPU and four pages in the low slot")
        args.protected_entry = True
    if args.cpuid and (not args.protected_entry or args.fpu or args.msrs):
        parser.error("--cpuid requires protected mode and a separate run from --fpu or --msrs")
    if args.mmio_write and (not args.long_mode or args.cpuid or args.fpu or args.msrs):
        parser.error("--mmio-write requires a separate long-mode run")
    if args.irqchip and (not args.protected_entry or args.long_mode or args.cpuid or args.two_vcpus):
        parser.error("--irqchip requires a single vCPU in 32-bit protected mode")
    if args.zero_slot and (not args.protected_entry or args.ram_pages < 258 or args.split_slot or
                           args.long_mode or args.irqchip or args.cpuid or args.two_vcpus):
        parser.error("--zero-slot requires one protected-mode vCPU and one slot of at least 258 pages")
    if args.pio and (not args.protected_entry or args.long_mode or args.cpuid or args.two_vcpus or args.zero_slot):
        parser.error("--pio requires a single protected-mode vCPU")
    if args.complete_read and not (args.pio or args.mmio_read):
        parser.error("--complete-read requires --pio or --mmio-read")
    if not 1 <= args.ram_pages <= MAX_SLOT_PAGES:
        parser.error(f"--ram-pages must be between 1 and {MAX_SLOT_PAGES}")
    if args.ram_pages > MAX_REAL_MODE_PAGES and not args.protected_entry:
        parser.error(f"--protected-entry is required above {MAX_REAL_MODE_PAGES} pages")
    if args.split_slot and (not args.protected_entry or args.ram_pages < 2):
        parser.error("--split-slot requires protected mode and at least two pages")
    if args.interrupt_run and not args.protected_entry:
        parser.error("--interrupt-run requires protected mode")
    if args.two_vcpus and not args.protected_entry:
        parser.error("--two-vcpus requires protected mode")
    if args.debugregs and (not args.protected_entry or args.two_vcpus or args.zero_slot or args.long_mode or
                           args.mmio_write or args.irqchip or args.cpuid):
        parser.error("--debugregs requires the single-vCPU protected-mode fixture")
    if args.xcrs and (not args.protected_entry or args.two_vcpus or args.zero_slot or args.long_mode or
                       args.mmio_write or args.irqchip):
        parser.error("--xcrs requires the single-vCPU protected-mode fixture")
    if args.xsave and (not args.protected_entry or args.two_vcpus or args.zero_slot or args.long_mode or
                       args.mmio_write or args.irqchip or args.xcrs):
        parser.error("--xsave requires a separate single-vCPU protected-mode fixture")
    qemu, kernel = (path.resolve(strict=True) for path in (args.qemu, args.kernel))
    output = args.output.resolve()
    if os.geteuid() != 0 or platform.machine() != "x86_64":
        parser.error("run as root on x86_64")
    if args.worker:
        print(json.dumps(exercise(qemu, kernel, output, args.reject_close, args.parent_engine, args.ram_pages,
                                  args.protected_entry, args.split_slot, args.interrupt_run,
                                  2 if args.two_vcpus else 1, args.long_mode, args.fpu, args.msrs, args.cpuid,
                                  args.mmio_write, args.mmio_read, args.ioeventfd, args.irqchip, args.pit,
                                  args.irqfd, args.zero_slot, args.tss, args.lapic, args.pio, args.complete_read,
                                  args.pio_boundary, args.pvh, args.irqchip_state, args.pit_state, args.debugregs,
                                  args.mp_state, args.xcrs, args.xsave, args.vcpu_events)))
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
        programs = [("kvm-run.c", client), ("init.c", init)]
        if args.parent_engine == "kvm":
            programs.append(("native-worker.c", output / "native-worker"))
        for source, binary in programs:
            HELPERS["run"](["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-pthread", SOURCES / source, "-o", binary],
                           20, output / f"{source}.log")
        report.update(client_sha256=HELPERS["digest"](client), module_sha256=HELPERS["digest"](module / "flexvm-pvkvm.ko"))
        if args.native_oracle:
            oracle = [client, str(args.ram_pages)]
            if args.protected_entry:
                oracle.append("split" if args.split_slot else "protected")
            if args.interrupt_run:
                oracle.append("interrupt")
            if args.two_vcpus:
                oracle.append("smp")
            if args.long_mode:
                oracle.append("long")
            if args.fpu:
                oracle.append("fpu")
            if args.msrs:
                oracle.append("msrs")
            if args.cpuid:
                oracle.append("cpuid")
            if args.mmio_write:
                oracle.append("mmio")
            if args.mmio_read:
                oracle.append("mmio-read")
            if args.ioeventfd:
                oracle.append("ioeventfd")
            if args.irqchip:
                oracle.append("irqchip")
            if args.pit:
                oracle.append("pit")
            if args.irqfd:
                oracle.append("irqfd")
            if args.zero_slot:
                oracle.append("zero-slot")
            if args.tss:
                oracle.append("tss")
            if args.lapic:
                oracle.append("lapic")
            if args.pio:
                oracle.append("pio")
            if args.complete_read:
                oracle.append("complete-read")
            if args.pio_boundary:
                oracle.append("pio-boundary")
            if args.pvh:
                oracle.append("pvh")
            if args.irqchip_state:
                oracle.append("irqchip-state")
            if args.pit_state:
                oracle.append("pit-state")
            if args.debugregs:
                oracle.append("debugregs")
            if args.mp_state:
                oracle.append("mp-state")
            if args.xcrs:
                oracle.append("xcrs")
            if args.xsave:
                oracle.append("xsave")
            if args.vcpu_events:
                oracle.append("vcpu-events")
            HELPERS["run"](oracle, 14 if args.interrupt_run else 8, output / "native-kvm.log")
            report["same_client_passed_native_kvm"] = True
            report["native_client_run_ns"] = client_timings((output / "native-kvm.log").read_text())
        files = {
            "kvm-run": client.read_bytes(), "flexvm-pvkvm.ko": (module / "flexvm-pvkvm.ko").read_bytes(),
            "ram-pages": str(args.ram_pages).encode("ascii"),
        }
        if args.protected_entry:
            files["split-slot" if args.split_slot else "protected-entry"] = b""
        if args.interrupt_run:
            files["interrupt-run"] = b""
        if args.two_vcpus:
            files["two-vcpus"] = b""
        if args.long_mode:
            files["long-mode"] = b""
        if args.fpu:
            files["floating-point"] = b""
        if args.msrs:
            files["boot-msrs"] = b""
        if args.cpuid:
            files["cpuid-profile"] = b""
        if args.mmio_write:
            files["mmio-write"] = b""
        if args.mmio_read:
            files["mmio-read"] = b""
        if args.ioeventfd:
            files["ioeventfd"] = b""
        if args.irqchip:
            files["irqchip"] = b""
        if args.pit:
            files["pit"] = b""
        if args.irqfd:
            files["irqfd"] = b""
        if args.zero_slot:
            files["zero-slot"] = b""
        if args.tss:
            files["tss"] = b""
        if args.lapic:
            files["lapic"] = b""
        if args.pio:
            files["pio"] = b""
        if args.complete_read:
            files["complete-read"] = b""
        if args.pio_boundary:
            files["pio-boundary"] = b""
        if args.pvh:
            files["pvh"] = b""
        if args.irqchip_state:
            files["irqchip-state"] = b""
        if args.pit_state:
            files["pit-state"] = b""
        if args.debugregs:
            files["debugregs"] = b""
        if args.mp_state:
            files["mp-state"] = b""
        if args.xcrs:
            files["xcrs"] = b""
        if args.xsave:
            files["xsave"] = b""
        if args.vcpu_events:
            files["vcpu-events"] = b""
        image = HELPERS["initramfs"](init.read_bytes(), files=files)
        (output / "initramfs").write_bytes(image)
        trace = output / "files.strace"
        worker = output / "worker.log"
        setup = """
            for path in /dev/kvm /dev/vhost-vsock /dev/vhost-net; do
                if [ "$path" = /dev/kvm ] && [ "$2" = kvm ]; then continue; fi
                if [ -e "$path" ]; then mount --bind "$1" "$path"; fi
            done
            shift 2
            exec "$@"
        """
        with tempfile.TemporaryDirectory(prefix="flexvm-parent-kvm-") as scratch:
            mask = Path(scratch) / "mask"
            mask.touch(mode=0o600)
            HELPERS["run"](["unshare", "--mount", "--propagation", "private", "sh", "-ec", setup, "sh", mask, args.parent_engine,
                            "strace", "-f", "-e", "trace=file", "-o", trace, sys.executable,
                            Path(__file__).resolve(), "--worker", "--qemu", qemu, "--kernel", kernel,
                            "--output", output, "--parent-engine", args.parent_engine,
                            "--ram-pages", str(args.ram_pages),
                            *(["--protected-entry"] if args.protected_entry else []),
                            *(["--split-slot"] if args.split_slot else []),
                            *(["--interrupt-run"] if args.interrupt_run else []),
                            *(["--two-vcpus"] if args.two_vcpus else []),
                            *(["--long-mode"] if args.long_mode else []),
                            *(["--fpu"] if args.fpu else []),
                            *(["--msrs"] if args.msrs else []),
                            *(["--cpuid"] if args.cpuid else []),
                            *(["--mmio-write"] if args.mmio_write else []),
                            *(["--mmio-read"] if args.mmio_read else []),
                            *(["--ioeventfd"] if args.ioeventfd else []),
                            *(["--irqchip"] if args.irqchip else []),
                            *(["--pit"] if args.pit else []),
                            *(["--irqfd"] if args.irqfd else []),
                            *(["--zero-slot"] if args.zero_slot else []),
                            *(["--tss"] if args.tss else []),
                            *(["--lapic"] if args.lapic else []),
                            *(["--pio"] if args.pio else []),
                            *(["--complete-read"] if args.complete_read else []),
                            *(["--pio-boundary"] if args.pio_boundary else []),
                            *(["--pvh"] if args.pvh else []),
                            *(["--irqchip-state"] if args.irqchip_state else []),
                            *(["--pit-state"] if args.pit_state else []),
                            *(["--debugregs"] if args.debugregs else []),
                            *(["--mp-state"] if args.mp_state else []),
                            *(["--xcrs"] if args.xcrs else []),
                            *(["--xsave"] if args.xsave else []),
                            *(["--vcpu-events"] if args.vcpu_events else []),
                            *(["--reject-close"] if args.reject_close else [])], 75, worker)
        lines = trace.read_text(errors="replace").splitlines()
        devices = {device for line in lines for device in DEVICES if f'"{device}"' in line}
        expected = {"/dev/kvm"} if args.parent_engine == "kvm" else set()
        if devices != expected:
            raise RuntimeError(f"unexpected virtualization device access: {sorted(devices)}")
        if args.parent_engine == "kvm":
            worker_path = f'execve("{output / "native-worker"}",'
            workers = {line.split()[0] for line in lines if worker_path in line and line.endswith(" = 0")}
            kvm_users = {line.split()[0] for line in lines if '"/dev/kvm"' in line}
            reset_queries = 2 if args.two_vcpus else 1
            model_queries = sum((args.cpuid, args.lapic, args.irqchip_state, args.debugregs, args.xcrs, args.xsave))
            model_queries += int(args.vcpu_events)
            model_queries += 2 * int(args.pit_state) + 3 * int(args.mp_state)
            if len(workers) != 1 + model_queries + reset_queries or kvm_users != workers:
                raise RuntimeError("only the native parent worker may use host KVM")
        report.update(json.loads(worker.read_text()), status="passed", host_device_access=bool(devices),
                      host_devices=sorted(devices))
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=str(error))
        print(error, file=sys.stderr)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}: {report_path}")
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
