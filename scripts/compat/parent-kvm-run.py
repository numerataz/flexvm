#!/usr/bin/env python3
"""Run a TCG or hardware KVM worker against a pinned page in shared outer RAM."""
import argparse
from contextlib import ExitStack
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
MAILBOX_SIZE = 64 << 10
PAGE_SIZE = 4096
OUTER_RAM_SIZE = 192 * MIB
IO_VALUES = (0x42, 0xa7)
OPEN_VM, CLOSE_VM, OPEN_CPU, CLOSE_CPU, RUN = range(1, 6)
QEMU_OPTIONS = [
    "-nodefaults", "-display", "none", "-monitor", "none", "-nic", "none",
    "-smp", "1", "-no-reboot", "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
]


def stop_process(process):
    if process.poll() is None:
        process.kill()
    process.wait()


class RunChannel:
    def __init__(self, connection):
        self.connection = connection
        self.exits = []
        self.timings = []
        try:
            self.connection.settimeout(3)
            if self.connection.recv(2) != b"R":
                raise RuntimeError("parent worker did not report readiness")
        except BaseException:
            self.connection.close()
            raise

    def run(self):
        started = time.monotonic()
        if select.select([self.connection], [], [], 0)[0]:
            raise RuntimeError("child replied before its next run request")
        self.connection.sendall(b"R")
        output = self.connection.recv(2)
        if len(output) != 1:
            raise RuntimeError("parent worker did not return one I/O byte")
        self.exits.append(output[0])
        self.timings.append(round((time.monotonic() - started) * 1000, 3))
        return output[0]

    def close(self):
        self.connection.close()


class TcgChild:
    def __init__(self, qemu, output, socket_path, outer_ram, offset):
        self.process = None
        self.channel = None
        self.memory = outer_ram
        self.offset = offset
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, (output / "child.log").open("wb") as log:
                listener.bind(str(socket_path))
                listener.listen(1)
                listener.settimeout(3)
                slot = (f"memory-backend-file,id=slot,mem-path=/proc/self/fd/{outer_ram},"
                        f"share=on,size=4K,offset={offset}")
                command = [
                    qemu, *QEMU_OPTIONS, "-machine", "pc,accel=tcg", "-m", "16", "-serial", "none",
                    "-object", slot, "-device", "flexvm-shared-ram,memdev=slot",
                    "-bios", output / "reset.rom", "-S", "-chardev", f"socket,id=port,path={socket_path}",
                    "-device", "isa-debugcon,iobase=0x30,chardev=port,run-control=on",
                ]
                self.process = subprocess.Popen(command, pass_fds=(outer_ram,), stdout=log, stderr=log)
                connection, _ = listener.accept()
                self.channel = RunChannel(connection)
        except BaseException:
            self.close()
            raise

    def run(self):
        if self.channel.exits and os.pread(self.memory, 1, self.offset + 0x22) != b"\0":
            raise RuntimeError("child wrote its second result while stopped")
        return self.channel.run()

    def close(self):
        if self.channel is not None:
            self.channel.close()
        if self.process is not None:
            stop_process(self.process)
            self.process = None


class KvmChild:
    def __init__(self, output, outer_ram, offset):
        self.process = None
        self.channel = None
        self.offset = offset
        connection, worker = socket.socketpair(type=socket.SOCK_SEQPACKET)
        try:
            with worker, (output / "child.log").open("wb") as log:
                control = worker.fileno()
                command = [output / "native-worker", str(control), str(outer_ram), str(offset)]
                self.process = subprocess.Popen(command, pass_fds=(control, outer_ram), stdout=log, stderr=log)
            self.channel = RunChannel(connection)
        except BaseException:
            connection.close()
            self.close()
            raise

    def run(self):
        return self.channel.run()

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


def doorbell_peer(server, memory, requests, replies):
    peer, _ = server.accept()
    try:
        peer.settimeout(3)
        # ivshmem protocol 0. The parent is peer 0 and the outer guest is peer 1.
        peer.sendall(struct.pack("<qq", 0, 1))
        for value, descriptor in ((-1, memory), (0, requests), (1, replies)):
            if socket.send_fds(peer, [struct.pack("<q", value)], [descriptor]) != 8:
                raise RuntimeError("short ivshmem setup message")
        return peer
    except BaseException:
        peer.close()
        raise


def exercise(qemu, kernel, output, reject_close, parent_engine):
    reset = bytearray(64 << 10)
    # The reset vector far-jumps to 0000:1000, the client's guest RAM.
    reset[0xfff0:0xfff5] = bytes.fromhex("ea00100000")
    (output / "reset.rom").write_bytes(reset)
    expected = (OPEN_VM, OPEN_CPU, RUN, RUN, CLOSE_CPU, CLOSE_VM)
    if reject_close:
        expected = expected[:-1]
    observed = []
    child = None
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
        struct.pack_into("<II", mapping, 0, 0x4d564b46, 3)
        outer_ram = os.memfd_create("flexvm-outer-ram", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        cleanup.callback(os.close, outer_ram)
        os.ftruncate(outer_ram, OUTER_RAM_SIZE)
        fcntl.fcntl(outer_ram, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        requests = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
        cleanup.callback(os.close, requests)
        replies = os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK)
        cleanup.callback(os.close, replies)
        command = [
            qemu, *QEMU_OPTIONS, "-machine", "q35,accel=tcg,memory-backend=outer-ram",
            "-cpu", "max,vmx=off,svm=off", "-m", "192",
            "-object", f"memory-backend-file,id=outer-ram,mem-path=/proc/self/fd/{outer_ram},share=on,size=192M",
            "-serial", "stdio", "-kernel", kernel, "-initrd", output / "initramfs",
            "-append", "console=ttyS0 loglevel=5 panic=1 rdinit=/init",
            "-chardev", f"socket,id=doorbell,path={control / 'doorbell'}",
            "-device", "ivshmem-doorbell,chardev=doorbell,vectors=1",
        ]
        with (output / "outer.log").open("wb") as log:
            outer = subprocess.Popen(command, pass_fds=(outer_ram,), stdout=log, stderr=log)
        cleanup.callback(stop_process, outer)
        cleanup.enter_context(doorbell_peer(server, memory, requests, replies))
        exited = os.pidfd_open(outer.pid)
        cleanup.callback(os.close, exited)
        deadline = time.monotonic() + 60
        while True:
            readable, _, _ = select.select([exited, requests], [], [], max(0, deadline - time.monotonic()))
            if exited in readable:
                break
            if requests not in readable:
                raise TimeoutError("outer guest did not shut down")
            if os.eventfd_read(requests) != 1:
                raise RuntimeError("multiple outstanding doorbell requests")
            pending, complete, opcode, _, length = struct.unpack_from("<IIIII", mapping, 8)
            if pending != complete + 1 or len(observed) >= len(expected) or opcode != expected[len(observed)]:
                raise RuntimeError(f"unexpected doorbell request {pending}, command {opcode}")
            offset, = struct.unpack_from("<Q", mapping, 32)
            status = 0
            if opcode == RUN:
                if length != PAGE_SIZE or offset % PAGE_SIZE or not MIB <= offset <= OUTER_RAM_SIZE - PAGE_SIZE:
                    raise RuntimeError("registered page is outside the outer VM RAM")
                if child is None:
                    if parent_engine == "kvm":
                        child = KvmChild(output, outer_ram, offset)
                    else:
                        child = TcgChild(qemu, output, control / "child.sock", outer_ram, offset)
                    cleanup.callback(child.close)
                if child.offset != offset:
                    raise RuntimeError("the registered page changed between runs")
                struct.pack_into("<I", mapping, 28, child.run())
            elif length or offset:
                raise RuntimeError(f"unexpected memory argument for command {opcode}")
            elif opcode == CLOSE_CPU:
                # The guest can unpin its page as soon as it sees this reply.
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
        if (outer.wait() != 0 or tuple(observed) != expected or child is None or tuple(child.channel.exits) != IO_VALUES
                or "PASS /dev/kvm returned two port I/O exits" not in guest
                or "PASS parent KVM guest shutdown" not in guest):
            raise RuntimeError(f"parent execution proof failed; commands={observed}, see outer.log")
        retained = "retaining a RAM page until the enclosing VM exits" in guest
        if retained != reject_close:
            raise RuntimeError("unexpected guest RAM pin disposition")
        if reject_close and (child.process is None or child.process.poll() is not None):
            raise RuntimeError("rejected close did not retain the child until enclosing cleanup")
    return {
        "guest_path": "/dev/kvm", "guest_vmx": False, "guest_svm": False,
        "parent_accelerator": parent_engine, "parent_commands": observed, "transport": "eventfd and MSI-X",
        "io_values": child.channel.exits, "child_memory_write_visible": True, "same_child_worker": True,
        "page_alias": True, "mapped_page_bytes": PAGE_SIZE,
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
    parser.add_argument("--reject-close", action="store_true", help="verify page retention when the parent refuses close")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    qemu, kernel = (path.resolve(strict=True) for path in (args.qemu, args.kernel))
    output = args.output.resolve()
    if os.geteuid() != 0 or platform.machine() != "x86_64":
        parser.error("run as root on x86_64")
    if args.worker:
        print(json.dumps(exercise(qemu, kernel, output, args.reject_close, args.parent_engine)))
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
            HELPERS["run"](["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", SOURCES / source, "-o", binary],
                           20, output / f"{source}.log")
        report.update(client_sha256=HELPERS["digest"](client), module_sha256=HELPERS["digest"](module / "flexvm-pvkvm.ko"))
        if args.native_oracle:
            HELPERS["run"]([client], 8, output / "native-kvm.log")
            report["same_client_passed_native_kvm"] = True
            report["native_client_run_ns"] = client_timings((output / "native-kvm.log").read_text())
        image = HELPERS["initramfs"](init.read_bytes(), files={
            "kvm-run": client.read_bytes(), "flexvm-pvkvm.ko": (module / "flexvm-pvkvm.ko").read_bytes(),
        })
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
