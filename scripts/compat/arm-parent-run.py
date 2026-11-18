#!/usr/bin/env python3
"""Run an ARM guest with the parent-owned KVM device and native child worker."""
import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import errno
import fcntl
import mmap
import os
from pathlib import Path
import platform
import runpy
import select
import socket
import struct
import tempfile

ROOT = Path(__file__).resolve().parent
PARENT = runpy.run_path(str(ROOT / "parent-kvm-run.py"))
SPAWN = PARENT["spawn_owned"]
ARM_RAM_BASE = 0x40000000
ARM_IPA_BITS_AT = 0x89138
ARM_VM_TYPE_AT = 0x89140
ARM_INIT_AT = 0x89300
ARM_REG_AT = 0x89400
ARM_REGS_AT = 0x96000
ARM_LANE_EVENT = 128
SYSTEM_EVENT = 24
ARM_IOCTL = dict(zip(range(38, 43), (1, 3, 4, 5, 6), strict=True))
CREATE_CPU, WORKER_RUN, REGISTER_RAM, OPEN_LANE, CANCEL_RUN, COMPLETE_READ, CLOSE_CPU = 2, 7, 8, 9, 10, 11, 12
REQUEST = struct.Struct("<IIII264s")
REPLY = struct.Struct("<iI256s")
MAX_REGS = 4096
LANE_STRIDE = PARENT["LANE_STRIDE"]
MIB = PARENT["MIB"]


def reply_from(connection):
    packet = connection.recv(REPLY.size + MAX_REGS * 8 + 1)
    if len(packet) < REPLY.size or len(packet) > REPLY.size + MAX_REGS * 8:
        raise RuntimeError("invalid native ARM reply size")
    status, reason, data = REPLY.unpack_from(packet)
    if not -4095 <= status <= 0:
        raise RuntimeError("invalid native ARM reply status")
    return status, reason, data, packet[REPLY.size:]


@dataclass
class Lane:
    socket: socket.socket
    sequence: int = 0
    live: tuple[int, int] | None = None
    cancelled: bool = False


class NativeArm:
    def __init__(self, binary, vm_type):
        self.control, peer = socket.socketpair(type=socket.SOCK_SEQPACKET)
        self.control.settimeout(3)
        self.lanes = {}
        proc = None
        try:
            with peer:
                descriptor = peer.fileno()
                proc = SPAWN([binary, str(descriptor), str(vm_type)], pass_fds=(descriptor,))
            status, reason, _, extra = reply_from(self.control)
            if reason or extra:
                raise RuntimeError("invalid native ARM VM creation response")
            if status:
                raise OSError(-status, os.strerror(-status))
        except BaseException:
            self.control.close()
            if proc:
                PARENT["stop_process"](proc)
            raise
        self.proc = proc

    def call(self, op, cpu=0, data=b"", sequence=0, fds=()):
        packet = REQUEST.pack(op, cpu, sequence, 0, data)
        sent = socket.send_fds(self.control, [packet], fds) if fds else self.control.send(packet)
        if sent != REQUEST.size:
            raise RuntimeError("short native ARM control command")
        status, reason, result, extra = reply_from(self.control)
        if reason or (extra and op != 4):
            raise RuntimeError("unexpected native ARM control payload")
        return status, result, extra

    def require(self, *args, **kwargs):
        status, data, extra = self.call(*args, **kwargs)
        if status:
            raise OSError(-status, os.strerror(-status))
        return data, extra

    def add_lane(self, cpu):
        if cpu in self.lanes:
            raise OSError(errno.EEXIST, "ARM vCPU lane already exists")
        lane, peer = socket.socketpair(type=socket.SOCK_SEQPACKET)
        try:
            with peer:
                self.require(OPEN_LANE, cpu=cpu, fds=(peer.fileno(),))
        except BaseException:
            lane.close()
            raise
        self.lanes[cpu] = Lane(lane)

    def close_cpu(self, cpu):
        try:
            self.require(CLOSE_CPU, cpu=cpu)
        except OSError as error:
            raise RuntimeError(f"failed to stop native ARM vCPU {cpu}") from error
        finally:
            lane = self.lanes.pop(cpu, None)
            if lane:
                lane.socket.close()

    def close(self):
        self.control.close()
        for lane in self.lanes.values():
            lane.socket.close()
        try:
            result = self.proc.wait(timeout=3)
        except BaseException:
            PARENT["stop_process"](self.proc)
            raise
        if result:
            raise RuntimeError(f"native ARM child exited with status {result}")


def register_slots(child, mailbox, total, outer_ram, outer_bytes, max_pages):
    slots = PARENT["read_registered_slots"](mailbox, total, max_pages, outer_bytes,
                                            outer_ram_base=ARM_RAM_BASE, min_gpa=ARM_RAM_BASE)
    for slot in slots:
        fd = os.memfd_create("arm-parent-slot", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            layout = struct.pack(f"<{len(slot.offsets)}Q", *slot.offsets)
            if os.write(fd, layout) != len(layout):
                raise RuntimeError("short write of native ARM slot layout")
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK |
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL)
            child.require(REGISTER_RAM, data=struct.pack("<QII", slot.gpa, slot.identifier, 0),
                          fds=(outer_ram, fd))
        finally:
            os.close(fd)


def service_lanes(worker, cpus, mailbox, replies, ready):
    for cpu, lane in worker.lanes.items():
        offset = PARENT["LANES_AT"] + cpu * LANE_STRIDE
        seq, ack, operation, _, cancelled = struct.unpack_from("<IIIiI", mailbox, offset)
        if lane.live is not None:
            issued, op = lane.live
            if issued != seq or operation != op or cancelled > issued:
                raise RuntimeError("ARM frontend changed a running request")
            if lane.socket in ready:
                status, reason, payload, extra = reply_from(lane.socket)
                if extra or (reason and (status or op != PARENT["RUN"])):
                    raise RuntimeError("invalid ARM vCPU reply")
                if not status and op == PARENT["RUN"]:
                    if reason == PARENT["KVM_EXIT_MMIO"]:
                        address, length, writing, data = struct.unpack_from("<QII8s", payload)
                        record = PARENT["EXIT_RECORD"].pack(reason, length, address, data, writing, 1)
                    elif reason == SYSTEM_EVENT:
                        mailbox[offset + ARM_LANE_EVENT:offset + ARM_LANE_EVENT + 136] = payload[:136]
                        record = PARENT["EXIT_RECORD"].pack(reason, 0, 0, bytes(8), 0, 0)
                    else:
                        raise RuntimeError(f"unsupported ARM KVM exit {reason}")
                    target = offset + PARENT["LANE_EXIT"]
                    mailbox[target:target + len(record)] = record
                struct.pack_into("<i", mailbox, offset + 12, status)
                struct.pack_into("<I", mailbox, offset + 4, issued)
                os.eventfd_write(replies, 1)
                lane.live = None
                lane.cancelled = False
            elif op == PARENT["RUN"] and cancelled == issued and not lane.cancelled:
                worker.require(CANCEL_RUN, cpu=cpu, sequence=lane.sequence)
                lane.cancelled = True
            continue
        if seq == ack:
            continue
        if cpu not in cpus or seq != ack + 1 or cancelled > seq or operation not in (PARENT["RUN"], PARENT["COMPLETE_READ"]):
            raise RuntimeError("invalid ARM vCPU request")
        lane.sequence += 1
        completion = offset + PARENT["LANE_COMPLETION"] + 8
        packet = REQUEST.pack(WORKER_RUN if operation == PARENT["RUN"] else COMPLETE_READ,
                              cpu, lane.sequence, 0, mailbox[completion:completion + 8])
        if lane.socket.send(packet) != REQUEST.size:
            raise RuntimeError("short ARM vCPU request")
        lane.live = (seq, operation)
        if operation == PARENT["RUN"] and cancelled == seq:
            worker.require(CANCEL_RUN, cpu=cpu, sequence=lane.sequence)
            lane.cancelled = True


def arm_ioctl(worker, mailbox, command, cpu):
    op = ARM_IOCTL[command]
    if op == 3:
        data = mailbox[ARM_INIT_AT:ARM_INIT_AT + 32]
    elif op == 4:
        data = mailbox[ARM_REGS_AT:ARM_REGS_AT + 8]
    elif op in (5, 6):
        data = mailbox[ARM_REG_AT:ARM_REG_AT + 264]
    else:
        data = b""
    status, result, extra = worker.call(op, cpu, data)
    if op == 1 and not status:
        mailbox[ARM_INIT_AT:ARM_INIT_AT + 32] = result[:32]
    elif op == 4 and status in (0, -errno.E2BIG):
        count, = struct.unpack_from("<Q", result)
        if count > MAX_REGS or len(extra) != (count * 8 if not status else 0):
            raise RuntimeError("invalid ARM register list")
        mailbox[ARM_REGS_AT:ARM_REGS_AT + 8 + len(extra)] = result[:8] + extra
    elif op == 5 and not status:
        mailbox[ARM_REG_AT + 8:ARM_REG_AT + 264] = result
    return status


def serve_commands(outer, mailbox, requests, cancellations, replies, binary, outer_ram, outer_bytes, max_pages):
    worker = None
    vm_open = False
    cpus = set()
    registered = False
    exited = os.pidfd_open(outer.pid)
    try:
        while True:
            lanes = [lane.socket for lane in worker.lanes.values() if lane.live] if worker else []
            readable, _, _ = select.select([exited, requests, cancellations, *lanes], [], [])
            if exited in readable:
                return outer.wait()
            for fd in (requests, cancellations):
                if fd in readable:
                    os.eventfd_read(fd)
            if worker:
                service_lanes(worker, cpus, mailbox, replies, readable)
            seq, ack, command, _, length = struct.unpack_from("<IIIII", mailbox, 8)
            if seq == ack:
                continue
            if seq != ack + 1 or (length and command != PARENT["PREPARE_RUN"]):
                raise RuntimeError("invalid ARM parent control sequence")
            cpu, = struct.unpack_from("<I", mailbox, 44)
            status = 0
            try:
                if command == PARENT["OPEN_VM"] and not vm_open:
                    vm_type, = struct.unpack_from("<Q", mailbox, ARM_VM_TYPE_AT)
                    worker = NativeArm(binary, vm_type)
                    vm_open = True
                    registered = False
                elif command == PARENT["CLOSE_VM"] and vm_open and not cpus:
                    closing, worker = worker, None
                    vm_open = False
                    closing.close()
                elif command == PARENT["CLOSE_CPU"] and worker and cpu in cpus:
                    worker.close_cpu(cpu)
                    cpus.remove(cpu)
                elif command == PARENT["OPEN_CPU"] and worker and cpu not in cpus:
                    worker.require(CREATE_CPU, cpu=cpu)
                    cpus.add(cpu)
                elif command == PARENT["PREPARE_RUN"] and worker and cpu in cpus:
                    if not registered:
                        if not length:
                            raise RuntimeError("ARM run has no registered RAM")
                        try:
                            register_slots(worker, mailbox, length, outer_ram, outer_bytes, max_pages)
                        except OSError as error:
                            raise RuntimeError("failed to install the ARM VM's RAM slots") from error
                        registered = True
                    elif length:
                        raise RuntimeError("ARM slots were registered twice")
                    worker.add_lane(cpu)
                elif command in ARM_IOCTL and worker and (command == 38 or cpu in cpus):
                    status = arm_ioctl(worker, mailbox, command, cpu)
                else:
                    status = -errno.ENOTTY
            except OSError as error:
                if error.errno is None:
                    raise
                status = -error.errno
            struct.pack_into("<i", mailbox, 20, status)
            struct.pack_into("<I", mailbox, 12, seq)
            os.eventfd_write(replies, 1)
    finally:
        try:
            if worker:
                worker.close()
        finally:
            os.close(exited)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "initrd", "worker"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--mem", type=int, default=256)
    parser.add_argument("--child-mem", type=int, default=128)
    args = parser.parse_args()
    if platform.machine() != "aarch64":
        parser.error("the native ARM parent requires an aarch64 Linux host")
    if not 128 <= args.mem <= 3072 or not 1 <= args.child_mem <= min(args.mem, 256):
        parser.error("invalid outer or child RAM size")
    worker = args.worker.resolve(strict=True)
    probe = PARENT["native_query"]([worker, "--ipa-bits"])
    if probe.returncode:
        raise RuntimeError(probe.stderr.decode(errors="replace"))
    ipa_bits = int(probe.stdout)

    with ExitStack() as resources:
        runtime = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="flexvm-arm-kvm-")))
        doorbell = runtime / "doorbell"
        server = resources.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        server.bind(str(doorbell))
        server.listen(1)
        server.settimeout(10)
        mailbox_fd = os.memfd_create("arm-parent-mailbox", os.MFD_CLOEXEC)
        resources.callback(os.close, mailbox_fd)
        os.ftruncate(mailbox_fd, PARENT["MAILBOX_SIZE"])
        mailbox = resources.enter_context(mmap.mmap(mailbox_fd, PARENT["MAILBOX_SIZE"]))
        struct.pack_into("<II", mailbox, 0, 0x4d564b46, 36)
        struct.pack_into("<I", mailbox, PARENT["FEATURES_AT"], 3)
        struct.pack_into("<I", mailbox, ARM_IPA_BITS_AT, ipa_bits)
        max_pages = args.child_mem * MIB // PARENT["PAGE_SIZE"]
        struct.pack_into("<I", mailbox, PARENT["RAM_LIMIT_AT"], max_pages)
        memory = os.memfd_create("flexvm-outer-ram", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        resources.callback(os.close, memory)
        outer_bytes = args.mem * MIB
        os.ftruncate(memory, outer_bytes)
        fcntl.fcntl(memory, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        requests, cancellations, replies = [os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK) for _ in range(3)]
        for fd in (requests, cancellations, replies):
            resources.callback(os.close, fd)
        command = [
            args.qemu.resolve(strict=True), "-machine", "virt,gic-version=3,memory-backend=outer-ram",
            "-accel", "tcg,thread=multi", "-cpu", "cortex-a72", "-m", str(args.mem), "-smp", "1",
            "-display", "none", "-monitor", "none", "-serial", "none", "-nodefaults", "-nic", "none", "-no-reboot",
            "-object", f"memory-backend-file,id=outer-ram,mem-path=/proc/self/fd/{memory},share=on,size={args.mem}M",
            "-chardev", "stdio,id=console,signal=off", "-device", "virtio-serial-device,id=serial",
            "-device", "virtconsole,chardev=console,bus=serial.0", "-kernel", args.kernel.resolve(strict=True),
            "-initrd", args.initrd.resolve(strict=True), "-append", "console=hvc0 quiet panic=1 rdinit=/init",
            "-chardev", f"socket,id=doorbell,path={doorbell}", "-device", "ivshmem-doorbell,chardev=doorbell,vectors=2",
        ]
        outer = SPAWN(command, pass_fds=(memory,))
        resources.callback(PARENT["stop_process"], outer)
        resources.enter_context(PARENT["doorbell_peer"](server, mailbox_fd, requests, cancellations, (), replies))
        return serve_commands(outer, mailbox, requests, cancellations, replies, worker, memory, outer_bytes, max_pages)


if __name__ == "__main__":
    raise SystemExit(main())
