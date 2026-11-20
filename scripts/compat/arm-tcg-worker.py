#!/usr/bin/env python3
"""ARM CPU execution for the parent-owned KVM device using QEMU TCG."""
from contextlib import ExitStack
import errno
import fcntl
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time

PREFERRED_TARGET, CREATE_CPU, INIT_CPU, GET_REG_LIST, GET_REG, SET_REG = range(1, 7)
REGISTER_RAM = 8
CREATE_DEVICE, CLOSE_DEVICE, GET_DEVICE_ATTR, SET_DEVICE_ATTR, HAS_DEVICE_ATTR, BIND_IRQFD = range(13, 19)
GET_MP_STATE, SET_MP_STATE = 19, 20
MP_RUNNABLE, MP_STOPPED = 0, 5
VGIC, ITS = 7, 8
CORE_X0 = 0x6030000000100000
CORE_PC = CORE_X0 + 64
CORE_PSTATE = CORE_X0 + 66
MPIDR = 0x603000000013c005
CORE_REGISTERS = (CORE_X0, CORE_PC, CORE_PSTATE)
REGISTERS = (*CORE_REGISTERS, MPIDR)
CORTEX_A57 = 5
PSCI_0_2 = 1 << 2
POWER_OFF = 1
MMIO_FIRST = 0x40000000
MMIO_LAST = 0x80000000
SYSTEM_EVENT = 24
STAGED_WORKER_STATE = b"FLEXVM ARM staged worker\n"


class TcgArm:
    def __init__(self, qemu, runtime, vm_type, *, checkpoint=False):
        if vm_type and not 32 <= vm_type <= 40:
            raise OSError(errno.EINVAL, "unsupported ARM TCG VM type")
        self.qemu = qemu
        self.runtime = runtime
        self.vm_type = vm_type
        self.checkpoint = checkpoint
        self.lanes = {}
        self.channels = {}
        self.cpus = {}
        self.initialized = set()
        self.powered = {}
        self.devices = set()
        self.device_config = {}
        self.irq_by_fd = {}
        self.slots = []
        self.proc = None
        self.qmp = None
        self.resources = ExitStack()
        self.process_resources = ExitStack()
        self.read_width = {}
        self.shutdown_reported = False

    def call(self, op, cpu=0, data=b"", fds=()):
        if op == GET_REG_LIST and cpu in self.initialized and struct.unpack("<Q", data)[0] < len(REGISTERS):
            return -errno.E2BIG, struct.pack("<Q", len(REGISTERS)), b""
        try:
            result, extra = self.control(op, cpu, data, fds)
        except OSError as error:
            if error.errno is None:
                raise
            return -error.errno, b"", b""
        return 0, result.ljust(256, b"\0"), extra

    def require(self, op, cpu=0, data=b"", fds=()):
        status, result, extra = self.call(op, cpu, data, fds)
        if status:
            raise OSError(-status, os.strerror(-status))
        return result, extra

    def control(self, op, cpu, data, fds):
        result = extra = b""
        if op == PREFERRED_TARGET:
            result = struct.pack("<I", CORTEX_A57)
        elif op == CREATE_CPU:
            if self.proc or cpu not in (0, 1) or cpu in self.cpus:
                raise OSError(errno.EINVAL, "invalid ARM TCG vCPU")
            self.cpus[cpu] = {CORE_X0: 0, CORE_PC: 0, CORE_PSTATE: 0x3c5}
        elif op == INIT_CPU:
            target, flags, *rest = struct.unpack("<8I", data)
            if self.proc or target != CORTEX_A57 or any(rest) or flags != PSCI_0_2 | (POWER_OFF if cpu else 0):
                raise OSError(errno.EINVAL, "unsupported ARM TCG vCPU initialization")
            self.initialized.add(cpu)
            self.powered[cpu] = not bool(flags & POWER_OFF)
        elif op == GET_REG_LIST:
            if cpu not in self.initialized:
                raise OSError(errno.ENOEXEC, "uninitialized ARM TCG vCPU")
            result = struct.pack("<Q", len(REGISTERS))
            extra = struct.pack(f"<{len(REGISTERS)}Q", *REGISTERS)
        elif op in (GET_REG, SET_REG):
            reg, value = struct.unpack_from("<QQ", data)
            if cpu not in self.initialized:
                raise OSError(errno.ENOEXEC, "uninitialized ARM TCG vCPU")
            if op == GET_REG and reg == MPIDR:
                result = struct.pack("<Q", 0x80000000 | cpu)
            elif reg not in CORE_REGISTERS:
                raise OSError(errno.ENOENT, "unsupported ARM TCG register")
            elif self.proc:
                raise OSError(errno.EBUSY, "ARM TCG boot state is already installed")
            elif op == SET_REG:
                self.cpus[cpu][reg] = value
            else:
                result = struct.pack("<Q", self.cpus[cpu][reg])
        elif op == REGISTER_RAM:
            address, slot, reserved = struct.unpack_from("<QII", data)
            if self.proc or reserved or address < MMIO_LAST or len(fds) != 2:
                raise OSError(errno.EINVAL, "invalid ARM TCG RAM slot")
            copies = []
            for fd in fds:
                copy = os.dup(fd)
                self.resources.callback(os.close, copy)
                copies.append(copy)
            self.slots.append((slot, address, *copies))
        elif CREATE_DEVICE <= op <= HAS_DEVICE_ATTR:
            result = self.device(op, data)
        elif op == BIND_IRQFD:
            gsi, = struct.unpack("<I", data)
            if gsi >= 96 or len(fds) != 1:
                raise OSError(errno.EINVAL, "invalid ARM TCG IRQFD")
            self.irq_by_fd[fds[0]] = gsi
        elif op in (GET_MP_STATE, SET_MP_STATE):
            result = self.mp_state(cpu, op, data)
        else:
            raise OSError(errno.ENOTTY, "unsupported ARM TCG control operation")
        return result, extra

    def mp_state(self, cpu, op, data):
        if cpu not in self.initialized:
            raise OSError(errno.ENOEXEC, "uninitialized ARM TCG vCPU")
        args = {"cpu-index": cpu}
        if op == SET_MP_STATE:
            state, = struct.unpack("<I", data)
            if state not in (MP_RUNNABLE, MP_STOPPED):
                raise OSError(errno.EINVAL, "invalid ARM TCG MP state")
            if cpu in self.read_width:
                raise OSError(errno.EBUSY, "ARM TCG vCPU is completing an MMIO read")
            args["runnable"] = state == MP_RUNNABLE
            if self.qmp is None:
                self.powered[cpu] = args["runnable"]
        runnable = self.ask("x-flexvm-arm-mp-state", args)["runnable"] if self.qmp else self.powered[cpu]
        return struct.pack("<I", MP_RUNNABLE if runnable else MP_STOPPED)

    def device(self, op, data):
        kind, flags, group, reserved, attr, value = struct.unpack("<IIIIQQ", data)
        if kind not in (VGIC, ITS) or reserved:
            raise OSError(errno.ENODEV, "unknown ARM TCG device")
        if op == CREATE_DEVICE:
            if flags == 1:
                return b""
            if flags or kind in self.devices or self.proc:
                raise OSError(errno.EINVAL, "invalid ARM TCG device creation")
            self.devices.add(kind)
            return b""
        if kind not in self.devices or flags:
            raise OSError(errno.ENODEV, "ARM TCG device is not open")
        if op == CLOSE_DEVICE:
            self.devices.remove(kind)
            return b""
        key = kind, group, attr
        supported = {(VGIC, 0, 2), (VGIC, 0, 3), (ITS, 0, 4),
                     (VGIC, 3, 0), (VGIC, 4, 0), (ITS, 4, 0)}
        if key not in supported:
            raise OSError(errno.ENXIO, "unsupported ARM TCG device attribute")
        if op == HAS_DEVICE_ATTR:
            return b""
        if op == GET_DEVICE_ATTR:
            if key not in self.device_config:
                raise OSError(errno.ENXIO, "unset ARM TCG device attribute")
            return struct.pack("<Q", self.device_config[key])
        if self.proc or (key == (VGIC, 3, 0) and value != 128):
            raise OSError(errno.EINVAL, "invalid ARM TCG interrupt configuration")
        self.device_config[key] = value
        return b""

    def ask(self, command, arguments):
        self.qmp.deadline = time.monotonic() + 3
        return self.qmp.ask(command, arguments)

    def add_lane(self, cpu):
        if self.proc is None:
            try:
                self.start()
            except BaseException:
                self.dispose_process()
                raise
        if cpu in self.lanes:
            raise OSError(errno.EEXIST, "ARM TCG lane already exists")
        self.lanes[cpu] = Lane(self.channels[cpu].connection)

    def start(self, *, incoming=None):
        if set(self.cpus) not in ({0}, {0, 1}) or self.cpus.keys() != self.initialized or not self.slots:
            raise OSError(errno.EINVAL, "incomplete ARM TCG boot configuration")
        if not {(VGIC, 4, 0), (ITS, 4, 0)} <= self.device_config.keys():
            raise OSError(errno.EINVAL, "incomplete ARM TCG interrupt configuration")
        try:
            gic = {
                "distributor": self.device_config[VGIC, 0, 2],
                "redistributor": self.device_config[VGIC, 0, 3],
                "its": self.device_config[ITS, 0, 4],
            }
        except KeyError as error:
            raise OSError(errno.EINVAL, "missing ARM TCG interrupt-controller address") from error
        tmp = Path(tempfile.mkdtemp(prefix="arm-", dir=self.runtime))
        self.process_resources.callback(shutil.rmtree, tmp)
        command = [
            self.qemu, "-machine", "virt,gic-version=3", "-accel", "tcg,thread=multi", "-cpu", "cortex-a72",
            "-m", "16", "-smp", str(len(self.cpus)), "-nodefaults", "-display", "none", "-serial", "none",
            "-monitor", "none", "-nic", "none", "-no-reboot", "-S", "-qmp", f"unix:{tmp / 'qmp'},server=on,wait=off",
        ]
        if incoming is not None:
            command.extend(["-incoming", "defer"])
        descriptors = []
        for slot, address, ram, layout in self.slots:
            device = f"flexvm-shared-ram,id=slot{slot},ram-fd={ram},layout-fd={layout},addr={address}"
            if self.checkpoint:
                device += ",external-ram-state=on"
            command.extend(["-device", device])
            descriptors.extend((ram, layout))
        with ExitStack() as listeners:
            sockets = []
            for cpu in self.cpus:
                path = tmp / f"r{cpu}"
                listener = listeners.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                listener.bind(str(path))
                listener.listen(1)
                listener.settimeout(3)
                sockets.append((cpu, listener))
                command.extend(["-chardev", f"socket,id=r{cpu},path={path}"])
            second = ",parallel-chardev=r1" if len(self.cpus) == 2 else ""
            device = f"flexvm-mmio-run,chardev=r0,addr={MMIO_FIRST},size={MMIO_LAST - MMIO_FIRST}{second}"
            if self.checkpoint:
                device += ",checkpoint-control=on"
            command.extend(["-device", device])
            self.proc = PARENT["spawn_owned"](command, pass_fds=descriptors, stdout=2)
            for cpu, listener in sockets:
                channel = PARENT["RunChannel"](listener.accept()[0])
                self.process_resources.callback(channel.close)
                self.channels[cpu] = channel
        self.qmp = PARENT["HELPERS"]["QMP"](tmp / "qmp", self.proc, time.monotonic() + 3)
        self.process_resources.callback(self.qmp.close)
        self.ask("x-flexvm-map-arm-gic", gic)
        if incoming is not None:
            self.freeze_run_control(True)
            self.qmp.deadline = time.monotonic() + 30
            transfer(self.qmp, incoming, incoming=True)
            if self.ask("query-status", {})["status"] != "paused":
                raise RuntimeError("restored ARM worker is not paused")
            return
        for cpu, values in self.cpus.items():
            self.ask("x-flexvm-set-arm-boot-registers", {
                "cpu-index": cpu, "pc": values[CORE_PC], "x0": values[CORE_X0], "pstate": values[CORE_PSTATE],
            })
            if self.powered[cpu] != (cpu == 0):
                self.ask("x-flexvm-arm-mp-state", {"cpu-index": cpu, "runnable": self.powered[cpu]})

    def capture(self, fd):
        if self.proc is None:
            if os.write(fd, STAGED_WORKER_STATE) != len(STAGED_WORKER_STATE):
                raise RuntimeError("short ARM staged worker state write")
        else:
            self.qmp.deadline = time.monotonic() + 30
            transfer(self.qmp, fd)

    def profile(self):
        profile = {
            "vm_type": self.vm_type,
            "cpus": sorted(self.cpus),
            "lanes": sorted(self.lanes),
            "devices": sorted(self.devices),
            "attributes": [[*key, value] for key, value in sorted(self.device_config.items())],
            "irqs": sorted(set(self.irq_by_fd.values())),
            "slots": [[slot, address, os.pread(layout, os.fstat(layout).st_size, 0).hex()]
                      for slot, address, _, layout in self.slots],
        }
        if self.proc is None:
            profile["boot"] = {
                "registers": [[self.cpus[cpu][register] for register in CORE_REGISTERS] for cpu in profile["cpus"]],
                "powered": [self.powered.get(cpu) for cpu in profile["cpus"]],
            }
        return profile

    def restore_cpus(self, profile, incoming):
        cpus, lanes = profile["cpus"], profile["lanes"]
        if "boot" in profile:
            size = len(STAGED_WORKER_STATE)
            if os.fstat(incoming).st_size != size or os.pread(incoming, size, 0) != STAGED_WORKER_STATE:
                raise RuntimeError("invalid ARM staged worker state")
            boot = profile["boot"]
            if lanes or cpus not in ([], [0], [1], [0, 1]) or len(boot["powered"]) != len(cpus) or len(boot["registers"]) != len(cpus):
                raise RuntimeError("invalid ARM staged CPU topology")
            powered, registers = boot["powered"], boot["registers"]
        else:
            if cpus not in ([0], [0, 1]) or len(set(lanes)) != len(lanes) or not set(lanes) <= set(cpus):
                raise RuntimeError("invalid ARM checkpoint CPU topology")
            powered, registers = [not cpu for cpu in cpus], [None] * len(cpus)
        for cpu, runnable, values in zip(cpus, powered, registers, strict=True):
            self.require(CREATE_CPU, cpu=cpu)
            if runnable is not None:
                if type(runnable) is not bool:
                    raise RuntimeError("invalid ARM staged CPU power state")
                self.require(INIT_CPU, cpu=cpu,
                             data=struct.pack("<8I", CORTEX_A57, PSCI_0_2 | (POWER_OFF if cpu else 0), *(0,) * 6))
                if self.powered[cpu] != runnable:
                    mp_state = MP_RUNNABLE if runnable else MP_STOPPED
                    self.require(SET_MP_STATE, cpu=cpu, data=struct.pack("<I", mp_state))
            if values is not None:
                if len(values) != len(CORE_REGISTERS) or any(type(value) is not int or not 0 <= value < 1 << 64 for value in values):
                    raise RuntimeError("invalid ARM staged CPU registers")
                for register, value in zip(CORE_REGISTERS, values, strict=True):
                    if runnable is not None:
                        self.require(SET_REG, cpu=cpu, data=struct.pack("<QQ", register, value))
                    elif value != self.cpus[cpu][register]:
                        raise RuntimeError("uninitialized ARM vCPU has staged registers")

    def restore(self, profile, ram, irq_fds, incoming, max_pages, outer_bytes):
        self.restore_cpus(profile, incoming)
        for kind in profile["devices"]:
            self.require(CREATE_DEVICE, data=struct.pack("<IIIIQQ", kind, 0, 0, 0, 0, 0))
        for kind, group, attr, value in profile["attributes"]:
            self.require(SET_DEVICE_ATTR, data=struct.pack("<IIIIQQ", kind, 0, group, 0, attr, value))
        if len(set(profile["irqs"])) != len(profile["irqs"]):
            raise RuntimeError("duplicate ARM checkpoint IRQ route")
        for gsi in profile["irqs"]:
            if not 0 <= gsi < len(irq_fds):
                raise RuntimeError("invalid ARM checkpoint IRQ route")
            self.require(BIND_IRQFD, data=struct.pack("<I", gsi), fds=(irq_fds[gsi],))
        seen_slots = set()
        seen_offsets = set()
        extents = []
        page = PARENT["PAGE_SIZE"]
        for slot, address, encoded in profile["slots"]:
            if not 0 <= slot < 8 or slot in seen_slots or address < MMIO_LAST or address % page:
                raise RuntimeError("invalid ARM checkpoint slot identity")
            wire = bytes.fromhex(encoded)
            if not wire or len(wire) % 8:
                raise RuntimeError("invalid ARM checkpoint slot layout")
            offsets = struct.unpack(f"<{len(wire) // 8}Q", wire)
            if (len(set(offsets)) != len(offsets) or any(offset % page or offset + page > outer_bytes or
                    offset in seen_offsets for offset in offsets) or len(seen_offsets) + len(offsets) > max_pages):
                raise RuntimeError("invalid ARM checkpoint slot offsets")
            end = address + len(offsets) * page
            if end > 0xc0000000 or any(address < old_end and old_address < end for old_address, old_end in extents):
                raise RuntimeError("overlapping ARM checkpoint slots")
            seen_slots.add(slot)
            seen_offsets.update(offsets)
            extents.append((address, end))
            fd = os.memfd_create("restored-arm-slot", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                if os.pwrite(fd, wire, 0) != len(wire):
                    raise RuntimeError("short ARM checkpoint slot layout write")
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK |
                            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL)
                self.require(REGISTER_RAM, data=struct.pack("<QII", address, slot, 0), fds=(ram, fd))
            finally:
                os.close(fd)
        if "boot" not in profile:
            self.start(incoming=incoming)
            for cpu in profile["lanes"]:
                self.add_lane(cpu)

    def checkpoint_ready(self):
        return not self.read_width and all(lane.live is None for lane in self.lanes.values())

    def can_capture(self):
        return self.proc is not None

    def freeze_run_control(self, frozen):
        if self.qmp and self.proc.poll() is None:
            self.ask("x-flexvm-freeze-run-control", {"frozen": frozen})

    def irq_descriptors(self):
        return self.irq_by_fd if self.proc and self.proc.poll() is None else ()

    def dispatch_irqs(self, ready):
        if self.proc and self.proc.poll() is None:
            for fd in self.irq_by_fd.keys() & set(ready):
                os.eventfd_read(fd)
                try:
                    self.ask("x-flexvm-pulse-arm-gsi", {"gsi": self.irq_by_fd[fd]})
                except (BrokenPipeError, ConnectionResetError, RuntimeError) as error:
                    # The child can leave QMP between the poll and this pulse.
                    try:
                        if self.proc.wait(timeout=0.2) == 0:
                            return
                    except subprocess.TimeoutExpired:
                        pass
                    raise error

    def run_request(self, cpu, operation, completion):
        if self.proc.poll() is not None:
            self.read_width.pop(cpu, None)
            return
        width = self.read_width.get(cpu, 0)
        if width > len(completion):
            raise RuntimeError("invalid ARM TCG MMIO completion width")
        if operation == PARENT["COMPLETE_READ"]:
            if not width:
                raise RuntimeError("no pending ARM TCG MMIO read")
            request = b"E" + completion[:width]
        elif width:
            request = b"D" + completion[:width]
        else:
            request = bytes((ord("R") + cpu,))
        try:
            self.lanes[cpu].socket.sendall(request)
        except BrokenPipeError:
            if self.proc.wait(timeout=3):
                raise
        self.read_width.pop(cpu, None)

    def run_reply(self, cpu, operation, cancelled):
        channel = self.channels[cpu]
        if operation == PARENT["COMPLETE_READ"]:
            packet = channel.connection.recv(1)
            if packet == b"E":
                return 0, 0, b""
            if packet:
                raise RuntimeError("invalid ARM TCG read completion response")
        else:
            packet = channel.read_exit()
        if not packet:
            if self.proc.wait(timeout=3):
                raise RuntimeError("ARM TCG worker stopped unexpectedly")
            if self.shutdown_reported or operation != PARENT["RUN"]:
                return -errno.EINTR, 0, b""
            self.shutdown_reported = True
            return 0, SYSTEM_EVENT, struct.pack("<II16Q", 1, 0, *(0,) * 16)
        if packet == b"I\0":
            if not cancelled:
                raise RuntimeError("unsolicited ARM TCG interruption")
            return -errno.EINTR, 0, b""
        result = PARENT["decode_run_exit"](packet)
        if result.reason != PARENT["KVM_EXIT_MMIO"]:
            raise RuntimeError("unexpected ARM TCG run output")
        if not result.is_write:
            self.read_width[cpu] = result.width
        return 0, result.reason, struct.pack("<QII8s", result.address, result.width, result.is_write, result.data)

    def cancel(self, cpu):
        if self.proc.poll() is None:
            try:
                self.lanes[cpu].socket.sendall(b"I")
            except BrokenPipeError:
                if self.proc.wait(timeout=3):
                    raise

    def close_cpu(self, cpu):
        channel = self.channels.pop(cpu, None)
        if channel:
            channel.close()
        self.lanes.pop(cpu, None)
        self.cpus.pop(cpu)
        self.read_width.pop(cpu, None)
        self.initialized.discard(cpu)
        self.powered.pop(cpu, None)

    def dispose_process(self):
        try:
            if self.proc:
                PARENT["stop_process"](self.proc)
        finally:
            self.process_resources.close()
            self.proc = self.qmp = None
            self.channels.clear()
            self.lanes.clear()
            self.read_width.clear()

    def close(self):
        try:
            self.dispose_process()
        finally:
            self.resources.close()
            self.irq_by_fd.clear()
