#!/usr/bin/env python3
"""Run an ARM guest with the parent-owned KVM device and native child worker."""
import argparse
from contextlib import ExitStack, suppress
from dataclasses import dataclass
import errno
import fcntl
import json
import mmap
import os
from pathlib import Path
import platform
import runpy
import select
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import time

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
ARM_DEVICE_AT = 0x89600
ARM_GSI_AT = 0x89620
ARM_MP_STATE_AT = 0x89624
ARM_GSI_COUNT = 128
CREATE_DEVICE, HAS_DEVICE_ATTR, GET_DEVICE_ATTR, BIND_IRQFD = 13, 17, 15, 18
GET_MP_STATE, SET_MP_STATE = 19, 20
SYSTEM_EVENT = 24
ARM_IOCTL = dict(zip(range(38, 51), (1, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18, 19, 20), strict=True))
VM_IOCTL = {38, *range(43, 49)}
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
    checkpoint_cancelled: bool = False
    completion_only: bool = False


class CheckpointGate:
    def __init__(self, listener):
        self.listener = listener
        self.client = None
        self.phase = "running"

    def descriptor(self):
        return self.client if self.client is not None else self.listener

    def service(self, ready, worker, capture):
        if self.descriptor() not in ready:
            return False
        if self.client is None:
            self.client, _ = self.listener.accept()
            return False
        request, fds, flags, _ = socket.recv_fds(self.client, 16, 3, socket.MSG_CMSG_CLOEXEC)
        with ExitStack() as descriptors:
            for fd in fds:
                descriptors.callback(os.close, fd)
                os.set_inheritable(fd, False)
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                raise RuntimeError("truncated ARM checkpoint request")
            return self.handle(request, fds, worker, capture)

    def handle(self, request, fds, worker, capture):
        if not request:
            self.close()
            if self.phase != "running":
                # The requester may have committed a captured VM elsewhere.
                # Unwind the broker and both owned emulators on disconnect.
                raise RuntimeError("ARM checkpoint owner disconnected")
        elif request == b"freeze" and not fds and self.phase == "running":
            self.phase = "freezing"
        elif request == b"thaw" and not fds and self.phase == "frozen":
            if worker:
                worker.freeze_run_control(False)
            self.phase = "running"
            self.client.sendall(b"ok")
        elif request == b"save" and len(fds) == 3 and self.phase == "frozen":
            capture(worker, fds)
            self.phase = "captured"
            self.client.sendall(b"ok")
        elif request == b"retire" and not fds and self.phase == "captured":
            return True
        else:
            self.client.sendall(b"invalid checkpoint command")
        return False

    def finish_freeze(self, worker):
        if self.phase != "freezing":
            return
        if worker:
            if worker.read_width or any(lane.live is not None for lane in worker.lanes.values()):
                return
            worker.freeze_run_control(True)
        self.phase = "frozen"
        self.client.sendall(b"ok")

    def close(self):
        if self.client is not None:
            self.client.close()
            self.client = None


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

    def irq_descriptors(self):
        return ()

    def dispatch_irqs(self, ready):
        pass

    def run_request(self, cpu, operation, completion):
        lane = self.lanes[cpu]
        packet = REQUEST.pack(WORKER_RUN if operation == PARENT["RUN"] else COMPLETE_READ,
                              cpu, lane.sequence, 0, completion)
        if lane.socket.send(packet) != REQUEST.size:
            raise RuntimeError("short native ARM vCPU request")

    def run_reply(self, cpu, operation, cancelled):
        status, reason, payload, extra = reply_from(self.lanes[cpu].socket)
        if extra or (reason and (status or operation != PARENT["RUN"])):
            raise RuntimeError("invalid native ARM vCPU reply")
        return status, reason, payload

    def cancel(self, cpu):
        self.require(CANCEL_RUN, cpu=cpu, sequence=self.lanes[cpu].sequence)

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


def acknowledge_lane(mailbox, replies, offset, issued, status):
    struct.pack_into("<i", mailbox, offset + 12, status)
    struct.pack_into("<I", mailbox, offset + 4, issued)
    os.eventfd_write(replies, 1)


def service_lanes(worker, cpus, mailbox, replies, ready, *, hold=False):
    for cpu, lane in worker.lanes.items():
        offset = PARENT["LANES_AT"] + cpu * LANE_STRIDE
        seq, ack, operation, _, cancelled = struct.unpack_from("<IIIiI", mailbox, offset)
        if lane.live is not None:
            issued, op = lane.live
            if issued != seq or operation != op or cancelled > issued:
                raise RuntimeError("ARM frontend changed a running request")
            if lane.socket in ready:
                worker_op = PARENT["COMPLETE_READ"] if lane.completion_only else op
                status, reason, payload = worker.run_reply(cpu, worker_op, cancelled == issued or lane.checkpoint_cancelled)
                if lane.completion_only and not status:
                    status = -errno.EINTR
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
                acknowledge_lane(mailbox, replies, offset, issued, status)
                lane.live = None
                lane.cancelled = lane.checkpoint_cancelled = lane.completion_only = False
            elif (op == PARENT["RUN"] and not lane.completion_only and not lane.cancelled and
                  (cancelled == issued or hold)):
                worker.cancel(cpu)
                lane.cancelled = True
                lane.checkpoint_cancelled = hold
            continue
        if seq == ack:
            continue
        if cpu not in cpus or seq != ack + 1 or cancelled > seq or operation not in (PARENT["RUN"], PARENT["COMPLETE_READ"]):
            raise RuntimeError("invalid ARM vCPU request")
        worker_op = operation
        if hold and operation == PARENT["RUN"]:
            if cpu not in worker.read_width:
                acknowledge_lane(mailbox, replies, offset, seq, -errno.EINTR)
                continue
            lane.completion_only = True
            worker_op = PARENT["COMPLETE_READ"]
        lane.sequence += 1
        completion = offset + PARENT["LANE_COMPLETION"] + 8
        worker.run_request(cpu, worker_op, mailbox[completion:completion + 8])
        lane.live = (seq, operation)
        if worker_op == PARENT["RUN"] and cancelled == seq:
            worker.cancel(cpu)
            lane.cancelled = True


def arm_ioctl(worker, mailbox, command, cpu, irq_fds):
    op = ARM_IOCTL[command]
    descriptors = ()
    if CREATE_DEVICE <= op <= HAS_DEVICE_ATTR:
        data = mailbox[ARM_DEVICE_AT:ARM_DEVICE_AT + 32]
    elif op == BIND_IRQFD:
        data = mailbox[ARM_GSI_AT:ARM_GSI_AT + 4]
        gsi, = struct.unpack("<I", data)
        if gsi >= len(irq_fds):
            return -errno.EINVAL
        descriptors = (irq_fds[gsi],)
    elif op == SET_MP_STATE:
        data = mailbox[ARM_MP_STATE_AT:ARM_MP_STATE_AT + 4]
    elif op == 3:
        data = mailbox[ARM_INIT_AT:ARM_INIT_AT + 32]
    elif op == 4:
        data = mailbox[ARM_REGS_AT:ARM_REGS_AT + 8]
    elif op in (5, 6):
        data = mailbox[ARM_REG_AT:ARM_REG_AT + 264]
    else:
        data = b""
    status, result, extra = worker.call(op, cpu, data, fds=descriptors)
    if op == GET_DEVICE_ATTR and not status:
        mailbox[ARM_DEVICE_AT + 24:ARM_DEVICE_AT + 32] = result[:8]
    elif op == GET_MP_STATE and not status:
        mailbox[ARM_MP_STATE_AT:ARM_MP_STATE_AT + 4] = result[:4]
    elif op == 1 and not status:
        mailbox[ARM_INIT_AT:ARM_INIT_AT + 32] = result[:32]
    elif op == 4 and status in (0, -errno.E2BIG):
        count, = struct.unpack_from("<Q", result)
        if count > MAX_REGS or len(extra) != (count * 8 if not status else 0):
            raise RuntimeError("invalid ARM register list")
        mailbox[ARM_REGS_AT:ARM_REGS_AT + 8 + len(extra)] = result[:8] + extra
    elif op == 5 and not status:
        mailbox[ARM_REG_AT + 8:ARM_REG_AT + 264] = result
    return status


def serve_commands(outer, mailbox, requests, cancellations, replies, irq_fds, create_worker, outer_ram, outer_bytes, max_pages,
                   gate=None, capture=None, worker=None):
    vm_open = worker is not None
    cpus = set(worker.cpus) if worker else set()
    registered = worker is not None
    exited = os.pidfd_open(outer.pid)
    try:
        while True:
            lanes = [lane.socket for lane in worker.lanes.values() if lane.live] if worker else []
            interrupts = worker.irq_descriptors() if worker and (not gate or gate.phase in ("running", "freezing")) else ()
            owner = [gate.descriptor()] if gate else []
            readable, _, _ = select.select([exited, requests, cancellations, *lanes, *interrupts, *owner], [], [])
            if exited in readable:
                return outer.wait()
            for fd in (requests, cancellations):
                if fd in readable:
                    os.eventfd_read(fd)
            if gate and gate.service(readable, worker, capture):
                return 0
            hold = gate is not None and gate.phase != "running"
            if worker:
                service_lanes(worker, cpus, mailbox, replies, readable, hold=hold)
                if not gate or gate.phase in ("running", "freezing"):
                    worker.dispatch_irqs(readable)
            if hold:
                gate.finish_freeze(worker)
                continue
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
                    for fd in irq_fds:
                        try:
                            os.eventfd_read(fd)
                        except BlockingIOError:
                            pass
                    worker = create_worker(vm_type)
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
                elif command in ARM_IOCTL and worker and (command in VM_IOCTL or cpu in cpus):
                    status = arm_ioctl(worker, mailbox, command, cpu, irq_fds)
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


def state_fds(fds, *, writing=False):
    identities = set()
    for fd in fds:
        mode = os.fstat(fd)
        identity = mode.st_dev, mode.st_ino
        access = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
        if not stat.S_ISREG(mode.st_mode) or identity in identities or os.lseek(fd, 0, os.SEEK_CUR):
            raise RuntimeError("ARM checkpoint needs distinct regular files positioned at zero")
        if (writing and access == os.O_RDONLY) or (not writing and access == os.O_WRONLY):
            raise RuntimeError("ARM checkpoint file access mode is invalid")
        identities.add(identity)
    return fds


def capture_state(outer, qmp, irq_fds, worker, fds):
    outer_fd, child_fd, metadata = state_fds(fds, writing=True)
    if worker is None or worker.proc is None:
        raise RuntimeError("ARM checkpoint needs an active nested worker")
    if any(os.fstat(fd).st_size for fd in fds):
        raise RuntimeError("ARM checkpoint output files must be empty")
    monitor = PARENT["HELPERS"]["QMP"](qmp, outer, time.monotonic() + 30)
    try:
        monitor.ask("stop")
        if monitor.ask("query-status")["status"] != "paused":
            raise RuntimeError("ARM checkpoint could not pause the outer VM")
        pending = {}
        for gsi, fd in enumerate(irq_fds):
            try:
                pending[gsi] = os.eventfd_read(fd)
            except BlockingIOError:
                pass
        worker.capture(child_fd)
        record = json.dumps({"version": 1, "worker": worker.profile(), "pending": pending}).encode()
        if os.write(metadata, record) != len(record):
            raise RuntimeError("short ARM checkpoint metadata write")
        transfer(monitor, outer_fd)
    finally:
        monitor.close()


def transfer(monitor, fd, *, incoming=False):
    monitor.send_fd(fd)
    try:
        monitor.ask("migrate-incoming" if incoming else "migrate", {"uri": "fd:snapshot"})
    except BaseException:
        with suppress(Exception):
            monitor.ask("closefd", {"fdname": "snapshot"})
        raise
    while True:
        result = monitor.ask("query-migrate")
        if result["status"] == "completed":
            return
        if result["status"] not in ("setup", "active", "device"):
            raise RuntimeError(f"ARM checkpoint state transfer failed: {result}")
        time.sleep(min(.01, monitor.remaining()))


def launch_arm(command, worker, memory_mib, child_mib, *, inherited=(), control=None, frontend=None,
               engine="kvm", tcg_qemu=None, emulator_fd=None, checkpoint=False, restore=None, qmp_path=None):
    ipa_bits = None
    if engine != "tcg":
        try:
            probe = PARENT["native_query"]([worker, "--ipa-bits"])
            if not probe.returncode:
                ipa_bits = int(probe.stdout)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if ipa_bits is None and engine == "kvm":
            raise RuntimeError("native ARM parent execution requires an available KVM worker")
    use_tcg = ipa_bits is None
    checkpoint = checkpoint and use_tcg
    if use_tcg:
        if tcg_qemu is None:
            raise RuntimeError("ARM TCG parent execution requires a software CPU engine")
        devices = PARENT["native_query"]([tcg_qemu, "-device", "help"])
        if any(device not in devices.stdout + devices.stderr for device in (b'"flexvm-mmio-run"', b'"flexvm-shared-ram"')):
            raise RuntimeError("ARM parent TCG requires the patched QEMU engine from scripts/build-qemu.sh")
        ipa_bits = 40
        if checkpoint and qmp_path is not None:
            options = PARENT["native_query"]([tcg_qemu, "-device", "flexvm-mmio-run,help"])
            checkpoint = b"checkpoint-control" in options.stdout + options.stderr

    with ExitStack() as resources:
        if control is None:
            runtime = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="flexvm-arm-kvm-")))
        else:
            runtime = control
            runtime.mkdir(mode=0o700)
            resources.callback(shutil.rmtree, runtime)
        gate = None
        if checkpoint:
            listener = resources.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET))
            listener.bind(str(runtime / "checkpoint"))
            listener.listen(1)
            gate = CheckpointGate(listener)
            resources.callback(gate.close)
            outer_qmp = qmp_path if qmp_path is not None else runtime / "outer-qmp"
            if qmp_path is None:
                command = [*command, "-qmp", f"unix:{outer_qmp},server=on,wait=off"]
            if restore:
                command.extend(["-incoming", "defer", "-S"])
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
        max_pages = child_mib * MIB // PARENT["PAGE_SIZE"]
        struct.pack_into("<I", mailbox, PARENT["RAM_LIMIT_AT"], max_pages)
        memory = os.memfd_create("flexvm-outer-ram", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        resources.callback(os.close, memory)
        outer_bytes = memory_mib * MIB
        os.ftruncate(memory, outer_bytes)
        fcntl.fcntl(memory, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        def eventfd():
            fd = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
            resources.callback(os.close, fd)
            return fd

        requests, cancellations, replies = (eventfd() for _ in range(3))
        irq_fds = tuple(eventfd() for _ in range(ARM_GSI_COUNT))
        command = [
            *command,
            "-object", f"memory-backend-file,id=outer-ram,mem-path=/proc/self/fd/{memory},share=on,size={memory_mib}M",
            "-chardev", f"socket,id=doorbell,path={doorbell}",
            "-device", f"ivshmem-doorbell,chardev=doorbell,vectors={2 + len(irq_fds)}",
        ]
        if checkpoint:
            command[-1] += ",master=on"
        if frontend is not None:
            block = json.dumps({"driver": "raw", "node-name": "parent-kvm-module", "read-only": True,
                                "file": {"driver": "file", "filename": str(frontend)}})
            # The root disk uses virtio-mmio and must remain /dev/vda.
            command.extend(["-blockdev", block, "-device", "virtio-blk-pci,drive=parent-kvm-module,serial=flexvm-pvkvm"])
        outer = SPAWN(command, pass_fds=(memory, *inherited))
        for fd in inherited:
            if use_tcg and fd == emulator_fd:
                resources.callback(os.close, fd)
            else:
                os.close(fd)
        resources.callback(PARENT["stop_process"], outer)
        resources.enter_context(PARENT["doorbell_peer"](server, mailbox_fd, requests, cancellations, irq_fds, replies,
                                                        guest_position=0 if checkpoint else 1))
        restored_worker = None
        if not use_tcg:
            def create_worker(vm_type):
                return NativeArm(worker, vm_type)
        else:
            setup = {"PARENT": PARENT, "Lane": Lane, "transfer": transfer}
            tcg_worker = runpy.run_path(str(ROOT / "arm-tcg-worker.py"), init_globals=setup)["TcgArm"]

            def create_worker(vm_type):
                return tcg_worker(tcg_qemu, runtime, vm_type, checkpoint=checkpoint)

            if restore:
                outer_fd, child_fd, metadata_fd = state_fds(restore)
                if not 0 < os.fstat(metadata_fd).st_size <= max_pages * 24 + 4096:
                    raise RuntimeError("invalid ARM checkpoint metadata size")
                record = json.loads(os.pread(metadata_fd, os.fstat(metadata_fd).st_size, 0))
                if not isinstance(record, dict) or record.get("version") != 1:
                    raise RuntimeError("unsupported ARM checkpoint metadata")
                monitor = PARENT["HELPERS"]["QMP"](outer_qmp, outer, time.monotonic() + 30)
                try:
                    transfer(monitor, outer_fd, incoming=True)
                    if monitor.ask("query-status")["status"] != "paused":
                        raise RuntimeError("restored ARM outer VM is not paused")
                finally:
                    monitor.close()
                restored_worker = create_worker(record["worker"]["vm_type"])
                resources.callback(restored_worker.close)
                restored_worker.restore(record["worker"], memory, irq_fds, child_fd, max_pages, outer_bytes)
                for gsi, count in record["pending"].items():
                    index = int(gsi)
                    if not 0 <= index < len(irq_fds) or not 0 < count < (1 << 64) - 1:
                        raise RuntimeError("invalid ARM checkpoint pending interrupt")
                    os.eventfd_write(irq_fds[index], count)
                os.eventfd_write(replies, 1)
                gate.phase = "frozen"

        def capture(worker, fds):
            capture_state(outer, outer_qmp, irq_fds, worker, fds)

        return serve_commands(outer, mailbox, requests, cancellations, replies, irq_fds, create_worker,
                              memory, outer_bytes, max_pages, gate=gate, capture=capture, worker=restored_worker)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "initrd"):
        parser.add_argument("--" + name, type=Path, required=True)
    engine = parser.add_mutually_exclusive_group(required=True)
    engine.add_argument("--worker", type=Path)
    engine.add_argument("--tcg", action="store_true")
    parser.add_argument("--checkpoint-control", type=Path)
    parser.add_argument("--restore-fds", nargs=3, type=int, metavar=("OUTER", "CHILD", "METADATA"))
    parser.add_argument("--mem", type=int, default=256)
    parser.add_argument("--child-mem", type=int, default=128)
    args = parser.parse_args()
    if args.restore_fds and not args.checkpoint_control:
        parser.error("restore needs a checkpoint control directory")
    if args.checkpoint_control and not args.tcg:
        parser.error("checkpoint control requires the ARM TCG worker")
    if args.worker and platform.machine() != "aarch64":
        parser.error("the native ARM parent requires an aarch64 Linux host")
    if not 128 <= args.mem <= 3072 or not 1 <= args.child_mem <= min(args.mem, 256):
        parser.error("invalid outer or child RAM size")
    command = [
        args.qemu.resolve(strict=True), "-machine", "virt,gic-version=3,memory-backend=outer-ram",
        "-accel", "tcg,thread=multi", "-cpu", "cortex-a72", "-m", str(args.mem), "-smp", "1",
        "-display", "none", "-monitor", "none", "-serial", "none", "-nodefaults", "-nic", "none", "-no-reboot",
        "-chardev", "stdio,id=console,signal=off", "-device", "virtio-serial-device,id=serial",
        "-device", "virtconsole,chardev=console,bus=serial.0", "-kernel", args.kernel.resolve(strict=True),
        "-initrd", args.initrd.resolve(strict=True), "-append", "console=hvc0 quiet panic=1 rdinit=/init",
    ]
    worker = args.worker.resolve(strict=True) if args.worker else None
    return launch_arm(command, worker, args.mem, args.child_mem, engine="tcg" if args.tcg else "kvm",
                      tcg_qemu=command[0], control=args.checkpoint_control, checkpoint=bool(args.checkpoint_control),
                      restore=args.restore_fds)


if __name__ == "__main__":
    raise SystemExit(main())
