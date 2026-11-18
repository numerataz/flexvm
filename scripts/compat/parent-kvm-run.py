#!/usr/bin/env python3
"""Run a parent worker against a pinned KVM memory slot in shared outer RAM."""
import argparse
from contextlib import ExitStack
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
OPEN_VM, CLOSE_VM, OPEN_CPU, CLOSE_CPU, RUN, GET_REGS, SET_REGS, GET_SREGS = range(1, 9)
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


def read_protected_entry(mailbox, slots, long_mode):
    record = mailbox[256:256 + SPECIAL_REGISTERS_SIZE]
    base, limit = DESCRIPTOR_TABLE.unpack_from(record, 8 * SEGMENT.size)
    control_at = 8 * SEGMENT.size + 2 * DESCRIPTOR_TABLE.size
    root = CONTROL_REGISTERS.unpack_from(record, control_at)[2]
    if limit != 23 or not slot_contains(slots, base, limit + 1):
        raise RuntimeError("protected entry GDT lies outside registered RAM")
    if long_mode and (root % PAGE_SIZE or not slot_contains(slots, root, PAGE_SIZE)):
        raise RuntimeError("long-mode page table root lies outside registered RAM")
    code = SEGMENT.pack(0, 0xffffffff, 8, 11, 1, 0, not long_mode, 1, long_mode, 1, 0, 0)
    data = SEGMENT.pack(0, 0xffffffff, 16, 3, 1, 0, 1, 1, 0, 1, 0, 0)
    controls = (CONTROL_REGISTERS.pack(1 | CR0_PAGING, 0, root, CR4_PAE, 0,
                                      EFER_LONG_MODE_ENABLE | EFER_LONG_MODE_ACTIVE, 0)
                if long_mode else CONTROL_REGISTERS.pack(1, 0, 0, 0, 0, 0, 0))
    expected = (code + data * 5 + bytes(2 * SEGMENT.size) + DESCRIPTOR_TABLE.pack(base, limit) +
                bytes(DESCRIPTOR_TABLE.size) + controls)
    if record != expected:
        raise RuntimeError("unsupported protected entry state")
    return record


def slot_contains(slots, address, size):
    return any(slot.gpa <= address and address + size <= slot.gpa + len(slot.offsets) * PAGE_SIZE for slot in slots)


def stop_process(process):
    if process.poll() is None:
        process.kill()
    process.wait()


class RunChannel:
    def __init__(self, connection):
        self.connection = connection
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

    def run(self, request, cancellation, interrupt):
        started = time.monotonic()
        if select.select([self.connection], [], [], 0)[0]:
            raise RuntimeError("child replied before its next run request")
        self.connection.sendall(request)
        interrupted = False
        while True:
            timeout = max(0, cancellation.deadline - time.monotonic())
            ready, _, _ = select.select([self.connection, cancellation.descriptor], [], [], timeout)
            if self.connection in ready:
                if cancellation.descriptor in ready:
                    cancellation.applies()
                break
            if cancellation.descriptor not in ready:
                raise TimeoutError("parent worker did not stop after KVM_RUN")
            if cancellation.applies() and not interrupted:
                interrupt()
                interrupted = True
        output = self.connection.recv(2)
        if len(output) == 1 and self.connection.type == socket.SOCK_STREAM:
            output += self.connection.recv(1)
        if output == b"I\0" and interrupted:
            self.interruptions.append(round((time.monotonic() - started) * 1000, 3))
            return None
        if len(output) != 2 or output[0] != ord("O"):
            raise RuntimeError("parent worker did not return a recognized stopped exit")
        self.exits.append(output[1])
        self.timings.append(round((time.monotonic() - started) * 1000, 3))
        return output[1]

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
    def __init__(self, qemu, output, socket_path, outer_ram, layouts, slots, cpu_count):
        self.process = None
        self.channel = None
        self.debugger = None
        self.special_monitor = None
        debugger_path = socket_path.with_name("registers.sock")
        self.special_monitor_path = socket_path.with_name("special-registers.sock")
        self.memory = outer_ram
        self.data_offset = slots[-1].offsets[-1] + 0x82
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, (output / "child.log").open("wb") as log:
                listener.bind(str(socket_path))
                listener.listen(1)
                listener.settimeout(3)
                command = [
                    qemu, *QEMU_OPTIONS, "-machine", "pc,accel=tcg", "-m", "16", "-smp", str(cpu_count), "-serial", "none",
                    "-bios", output / "reset.rom", "-S", "-chardev", f"socket,id=port,path={socket_path}",
                    "-chardev", f"socket,id=regs,path={debugger_path},server=on,wait=off",
                    "-gdb", "chardev:regs",
                    "-qmp", f"unix:{self.special_monitor_path},server=on,wait=off",
                    "-device", "isa-debugcon,iobase=0x30,chardev=port,run-control=on",
                ]
                for slot, layout in zip(slots, layouts, strict=True):
                    command.extend(["-device", f"flexvm-shared-ram,id=slot{slot.identifier},"
                                    f"ram-fd={outer_ram},layout-fd={layout},addr={slot.gpa}"])
                self.process = subprocess.Popen(command, pass_fds=(outer_ram, *layouts), stdout=log, stderr=log)
                connection, _ = listener.accept()
                self.channel = RunChannel(connection)
                self.debugger = RegisterChannel(debugger_path)
                description = self.debugger.exchange("qXfer:features:read:target.xml:0,fff")
                if b'<xi:include href="i386-64bit.xml"/>' not in description:
                    raise RuntimeError("unexpected QEMU register layout")
                for cpu in range(cpu_count):
                    self.debugger.select_cpu(cpu)
                    self.debugger.write(18, 4, 0)  # Real-mode code segment with zero base.
        except BaseException:
            self.close()
            raise

    def run(self, cpu, cancellation):
        if self.channel.exits and os.pread(self.memory, 1, self.data_offset) != b"\0":
            raise RuntimeError("child wrote its second result while stopped")
        request = bytes((ord("R") + cpu,))
        return self.channel.run(request, cancellation, lambda: self.channel.connection.sendall(b"I"))

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
        self.special_command("x-flexvm-set-x86-protected-entry", arguments)

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
    def __init__(self, output, outer_ram, layouts, slots, cpu_count):
        self.process = None
        self.channel = None
        self.sigqueue = ctypes.CDLL(None, use_errno=True).sigqueue
        self.sigqueue.argtypes = (ctypes.c_int, ctypes.c_int, SignalValue)
        self.sigqueue.restype = ctypes.c_int
        connection, worker = socket.socketpair(type=socket.SOCK_SEQPACKET)
        try:
            with worker, (output / "child.log").open("wb") as log:
                control = worker.fileno()
                command = [output / "native-worker", str(control), str(outer_ram), str(cpu_count)]
                for slot, layout in zip(slots, layouts, strict=True):
                    command.extend(map(str, (layout, slot.gpa, slot.identifier)))
                self.process = subprocess.Popen(command, pass_fds=(control, outer_ram, *layouts), stdout=log, stderr=log)
            self.channel = RunChannel(connection)
        except BaseException:
            connection.close()
            self.close()
            raise

    def run(self, cpu, cancellation):
        sequence = cancellation.sequence
        if not 0 < sequence < 1 << 31:
            raise RuntimeError("invalid native cancellation sequence")
        return self.channel.run(struct.pack("<cBI", b"R", cpu, sequence), cancellation,
                                lambda: self.interrupt(sequence))

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


def doorbell_peer(server, memory, requests, cancellations, replies, unused_vector):
    peer, _ = server.accept()
    try:
        peer.settimeout(3)
        # ivshmem protocol 0. The parent is peer 0 and the outer guest is peer 1.
        peer.sendall(struct.pack("<qq", 0, 1))
        for value, descriptor in ((-1, memory), (0, requests), (0, cancellations),
                                  (1, replies), (1, unused_vector)):
            if socket.send_fds(peer, [struct.pack("<q", value)], [descriptor]) != 8:
                raise RuntimeError("short ivshmem setup message")
        return peer
    except BaseException:
        peer.close()
        raise


def read_slot_table(mailbox, ram_pages, outer_bytes, protected_entry, split_slot):
    first_gpa = PROTECTED_GPA if protected_entry else PAGE_SIZE
    expected = [(0, ram_pages, first_gpa)]
    if split_slot:
        first_pages = ram_pages // 2
        expected = [(0, first_pages, first_gpa), (5, ram_pages - first_pages, SPLIT_GPA)]
    count, = struct.unpack_from("<I", mailbox, 32)
    if count != len(expected) or count > MAX_SLOTS:
        raise RuntimeError("unexpected number of registered RAM slots")
    slots = []
    used_offsets = set()
    offset_position = 1024
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


def start_child(engine, qemu, output, control, outer_ram, slots, cpu_count):
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
            return KvmChild(output, outer_ram, layouts, slots, cpu_count)
        return TcgChild(qemu, output, control / "child.sock", outer_ram, layouts, slots, cpu_count)


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
             split_slot, interrupt_run, cpu_count, long_mode):
    reset = bytearray(64 << 10)
    reset[0xfff0] = 0xf4  # Halt if register setup did not select the client's code.
    (output / "reset.rom").write_bytes(reset)
    expected_interruptions = TEST_INTERRUPTS if interrupt_run else 0
    expected = [OPEN_VM, *([OPEN_CPU] * cpu_count), RUN, GET_REGS, GET_SREGS]
    expected_counters = [0x1357]
    expected_io = [(0, 0x42)]
    if cpu_count == 2:
        expected.extend((RUN, GET_REGS, GET_REGS, CLOSE_CPU))
        expected_counters.extend((0x3344, 0x1357))
        expected_io.append((1, 0x56))
    expected.extend((SET_REGS, GET_REGS, *((RUN, GET_REGS) * expected_interruptions), RUN, GET_REGS, CLOSE_CPU, CLOSE_VM))
    expected_counters.extend((*([0x3579] * (1 + expected_interruptions)), 0x2468))
    expected_io.append((0, 0xa7))
    if reject_close:
        expected = expected[:-1]
    observed = []
    counters = []
    io_events = []
    open_cpus = set()
    started_cpus = set()
    special = None
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
        struct.pack_into("<II", mapping, 0, 0x4d564b46, 14)
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
        unused_vector = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
        cleanup.callback(os.close, unused_vector)
        command = [
            qemu, *QEMU_OPTIONS, "-machine", "q35,accel=tcg,memory-backend=outer-ram",
            "-cpu", "max,vmx=off,svm=off", "-m", str(outer_mib), "-smp", "1",
            "-object", f"memory-backend-file,id=outer-ram,mem-path=/proc/self/fd/{outer_ram},share=on,size={outer_mib}M",
            "-serial", "stdio", "-kernel", kernel, "-initrd", output / "initramfs",
            "-append", "console=ttyS0 loglevel=5 panic=1 rdinit=/init",
            "-chardev", f"socket,id=doorbell,path={control / 'doorbell'}",
            "-device", "ivshmem-doorbell,chardev=doorbell,vectors=2",
        ]
        with (output / "outer.log").open("wb") as log:
            outer = subprocess.Popen(command, pass_fds=(outer_ram,), stdout=log, stderr=log)
        cleanup.callback(stop_process, outer)
        cleanup.enter_context(doorbell_peer(server, memory, requests, cancellations, replies, unused_vector))
        exited = os.pidfd_open(outer.pid)
        cleanup.callback(os.close, exited)
        deadline = time.monotonic() + 60
        while True:
            readable, _, _ = select.select([exited, requests, cancellations], [], [], max(0, deadline - time.monotonic()))
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
            if requests not in readable:
                raise TimeoutError("outer guest did not shut down")
            if os.eventfd_read(requests) != 1:
                raise RuntimeError("multiple outstanding doorbell requests")
            pending, complete, opcode, _, length = struct.unpack_from("<IIIII", mapping, 8)
            if pending != complete + 1 or len(observed) >= len(expected) or opcode != expected[len(observed)]:
                raise RuntimeError(f"unexpected doorbell request {pending}, command {opcode}")
            cpu, = struct.unpack_from("<I", mapping, 44)
            if opcode in (CLOSE_CPU, RUN, GET_REGS, GET_SREGS, SET_REGS) and cpu not in open_cpus:
                raise RuntimeError(f"command {opcode} requested unopened vCPU {cpu}")
            status = 0
            if opcode == OPEN_CPU:
                if length or cpu >= cpu_count or cpu in open_cpus:
                    raise RuntimeError(f"invalid request to create vCPU {cpu}")
                open_cpus.add(cpu)
            elif opcode == RUN:
                if child is None:
                    if length != slot_size or len(open_cpus) != cpu_count:
                        raise RuntimeError("unexpected total size of registered RAM")
                    slots = read_slot_table(mapping, ram_pages, outer_ram_size, protected_entry, split_slot)
                    child = start_child(parent_engine, qemu, output, control, outer_ram, slots, cpu_count)
                    cleanup.callback(child.close)
                    extents = verify_slot_spans(child.process.pid, slots)
                elif length:
                    raise RuntimeError("unexpected slot registration after the first run")
                if cpu not in started_cpus:
                    if protected_entry:
                        state = read_protected_entry(mapping, slots, long_mode)
                        child.set_protected_entry(cpu, state)
                    child.set_registers(cpu, mapping[64:64 + REGISTERS.size])
                    started_cpus.add(cpu)
                value = child.run(cpu, RunCancellation(cancellations, mapping, pending, deadline))
                if value is None:
                    status = -errno.EINTR
                else:
                    io_events.append((cpu, value))
                    struct.pack_into("<I", mapping, 28, value)
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
                }
                control_state = CONTROL_REGISTERS.unpack_from(registers, 8 * SEGMENT.size + 2 * DESCRIPTOR_TABLE.size)
                special.update(cr0=control_state[0], cr2=control_state[1], cr3=control_state[2],
                               cr4=control_state[3], efer=control_state[5])
            elif opcode == CLOSE_CPU:
                open_cpus.remove(cpu)
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
                or len(child.channel.interruptions) != expected_interruptions or counters != expected_counters
                or interrupt_run and "PASS stopped and resumed the same running child" not in guest
                or cpu_count == 2 and "PASS two vCPUs kept independent state in one child" not in guest
                or long_mode and "PASS x86-64 child used guest page tables and a virtual RAM alias" not in guest
                or "PASS /dev/kvm returned two port I/O exits" not in guest
                or "PASS parent KVM guest shutdown" not in guest):
            raise RuntimeError(f"parent execution proof failed; commands={observed}, see outer.log")
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
    parser.add_argument("--reject-close", action="store_true", help="verify page retention when the parent refuses close")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.long_mode:
        if args.two_vcpus or args.ram_pages < (8 if args.split_slot else 4):
            parser.error("--long-mode requires one vCPU and four pages in the low slot")
        args.protected_entry = True
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
    qemu, kernel = (path.resolve(strict=True) for path in (args.qemu, args.kernel))
    output = args.output.resolve()
    if os.geteuid() != 0 or platform.machine() != "x86_64":
        parser.error("run as root on x86_64")
    if args.worker:
        print(json.dumps(exercise(qemu, kernel, output, args.reject_close, args.parent_engine, args.ram_pages,
                                  args.protected_entry, args.split_slot, args.interrupt_run,
                                  2 if args.two_vcpus else 1, args.long_mode)))
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
            if len(workers) != 1 or kvm_users != workers:
                raise RuntimeError("only the native parent worker may use host KVM")
        report.update(json.loads(worker.read_text()), status="passed", host_device_access=bool(devices),
                      host_devices=sorted(devices))
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=str(error))
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}: {report_path}")
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
