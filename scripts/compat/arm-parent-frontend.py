#!/usr/bin/env python3
"""Exercise the ARM parent KVM device's PCI probe and VM control handshake."""
import argparse
from contextlib import ExitStack
import mmap
import os
from pathlib import Path
import runpy
import select
import socket
import struct
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
PARENT = runpy.run_path(str(ROOT / "parent-kvm-run.py"))
HELPERS = PARENT["HELPERS"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("qemu", "kernel", "bundle", "output"):
        parser.add_argument("--" + argument, type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--native", action="store_true", help="run the KVM ABI client through a native ARM child")
    mode.add_argument("--checkpoint", action="store_true", help="restore an in-flight request against a fresh mailbox")
    mode.add_argument("--initial-state", action="store_true", help="checkpoint open ARM KVM descriptors before first KVM_RUN")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir()
    init = output / "init"
    cc = [args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static"]
    flags = ["-DFLEXVM_ARM_NATIVE_TEST"] if args.native else []
    if args.initial_state:
        flags.append("-DFLEXVM_ARM_INITIAL_STATE_TEST")
    HELPERS["run"]([*cc, *flags, ROOT / "parent-kvm/arm-frontend-probe.c", "-o", init], 30, output / "build.log")
    module = (args.bundle / "flexvm-pvkvm.ko").read_bytes()
    abi = None
    if args.native:
        client = output / "abi-client"
        HELPERS["run"]([*cc, ROOT / "kvm-arm.c", "-o", client], 30, output / "abi-build.log")
        abi = client.read_bytes()
    cpio = output / "initramfs"
    cpio.write_bytes(HELPERS["initramfs"](init.read_bytes(), kvm=abi, files={"flexvm-pvkvm.ko": module}))
    if args.native:
        log = output / "guest.log"
        HELPERS["run"]([
            sys.executable, ROOT / "arm-parent-run.py", "--qemu", args.qemu, "--kernel", args.kernel,
            "--initrd", cpio, "--worker", args.bundle / "native-worker",
        ], 120, log)
        if "PASS ARM parent-owned KVM device ran the unmodified ABI client" not in log.read_text(errors="replace"):
            raise RuntimeError(f"ARM native worker acceptance failed; see {log}")
        print("PASS ARM parent-owned KVM ABI execution")
        return

    if args.initial_state:
        capture = runpy.run_path(str(ROOT / "arm-parent-firecracker.py"))["transfer_checkpoint"]
        log = output / "guest.log"
        capture([sys.executable, ROOT / "arm-parent-run.py", "--qemu", args.qemu, "--kernel", args.kernel,
                 "--initrd", cpio, "--tcg"], output, log, window="ARM checkpoint window before first KVM_RUN")
        if (output / "target.log").read_text(errors="replace").splitlines().count("PASS ARM pending vCPU configuration survived checkpoint") != 1:
            raise RuntimeError(f"ARM pre-run checkpoint failed; see {log}")
        print("PASS ARM pre-run checkpoint restored staged registers and vCPU power state")
    elif args.checkpoint:
        with tempfile.TemporaryFile() as snapshot:
            exercise(args, cpio, output, snapshot=snapshot)
            snapshot.seek(0)
            exercise(args, cpio, output, snapshot=snapshot, incoming=True)
        print("PASS ARM parent frontend resumed an in-flight mailbox request")
    else:
        exercise(args, cpio, output)
        print("PASS ARM parent KVM frontend handshake")


def wait_transfer(monitor):
    while True:
        state = monitor.ask("query-migrate")
        if state.get("status") == "completed":
            return
        if state.get("status") not in ("setup", "active", "device"):
            raise RuntimeError(f"unexpected ARM parent transfer state: {state}")
        time.sleep(min(.01, monitor.remaining()))


def exercise(args, cpio, output, *, snapshot=None, incoming=False):
    with ExitStack() as resources:
        runtime = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="flexvm-arm-front-")))
        doorbell = runtime / "doorbell"
        server = resources.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        server.bind(str(doorbell))
        server.listen(1)
        server.settimeout(5)
        memory = os.memfd_create("arm-parent-mailbox", os.MFD_CLOEXEC)
        resources.callback(os.close, memory)
        os.ftruncate(memory, PARENT["MAILBOX_SIZE"])
        mailbox = resources.enter_context(mmap.mmap(memory, PARENT["MAILBOX_SIZE"]))
        struct.pack_into("<II", mailbox, 0, 0x4d564b46, 36)
        struct.pack_into("<I", mailbox, PARENT["FEATURES_AT"], 2)
        struct.pack_into("<I", mailbox, 0x89138, 48)
        requests, cancellations, replies = [os.eventfd(0, os.EFD_CLOEXEC | os.EFD_NONBLOCK) for _ in range(3)]
        for fd in (requests, cancellations, replies):
            resources.callback(os.close, fd)

        qmp = runtime / "qmp"
        guest_position = 0 if snapshot is not None else 1
        device = "ivshmem-doorbell,chardev=doorbell,vectors=2"
        if snapshot is not None:
            device += ",master=on"
        command = [
            args.qemu.resolve(strict=True), "-machine", "virt,gic-version=3", "-accel", "tcg,thread=multi",
            "-cpu", "cortex-a72", "-m", "256", "-smp", "1", "-display", "none", "-monitor", "none",
            "-serial", "none", "-nodefaults", "-nic", "none", "-no-reboot",
            "-chardev", "stdio,id=console,signal=off", "-device", "virtio-serial-device,id=serial",
            "-device", "virtconsole,chardev=console,bus=serial.0", "-kernel", args.kernel.resolve(strict=True),
            "-initrd", cpio, "-append", "console=hvc0 quiet panic=1 rdinit=/init",
            "-chardev", f"socket,id=doorbell,path={doorbell}", "-device", device,
        ]
        if snapshot is not None:
            command.extend(["-qmp", f"unix:{qmp},server=on,wait=off"])
        if incoming:
            command.extend(["-incoming", "defer", "-S"])

        def verify_handshake(proc, deadline):
            peer = PARENT["doorbell_peer"](server, memory, requests, cancellations, (), replies,
                                           guest_position=guest_position)
            resources.enter_context(peer)
            exited = os.pidfd_open(proc.pid)
            resources.callback(os.close, exited)

            def check_request(expected, *, restored=False):
                if not restored:
                    ready, _, _ = select.select([requests, exited], [], [], max(0, deadline - time.monotonic()))
                    if requests not in ready or os.eventfd_read(requests) != 1:
                        raise RuntimeError(f"ARM probe did not send expected request {expected}")
                pending, complete, command = struct.unpack_from("<III", mailbox, 8)
                if pending != complete + 1 or command != expected:
                    raise RuntimeError(f"unexpected ARM request {command}")
                if command == PARENT["OPEN_VM"] and struct.unpack_from("<Q", mailbox, 0x89140) != (48,):
                    raise RuntimeError("ARM VM request did not preserve the IPA size")
                return pending

            def reply(pending):
                struct.pack_into("<i", mailbox, 20, 0)
                struct.pack_into("<I", mailbox, 12, pending)
                os.eventfd_write(replies, 1)

            if snapshot is None:
                reply(check_request(PARENT["OPEN_VM"]))
            else:
                monitor = HELPERS["QMP"](qmp, proc, deadline)
                resources.callback(monitor.close)
                if not incoming:
                    check_request(PARENT["OPEN_VM"])
                    monitor.ask("stop")
                    monitor.send_fd(snapshot.fileno())
                    monitor.ask("migrate", {"uri": "fd:snapshot"})
                    wait_transfer(monitor)
                    monitor.ask("quit")
                    return
                monitor.send_fd(snapshot.fileno())
                monitor.ask("migrate-incoming", {"uri": "fd:snapshot"})
                wait_transfer(monitor)
                if monitor.ask("query-status")["status"] != "paused":
                    raise RuntimeError("ARM parent resumed before the mailbox was ready")
                reply(check_request(PARENT["OPEN_VM"], restored=True))
                monitor.ask("cont")
            reply(check_request(PARENT["CLOSE_VM"]))

        suffix = "target" if incoming else "source" if snapshot is not None else "guest"
        log = output / f"{suffix}.log"
        HELPERS["run"](command, 45, log, during=verify_handshake)
        if (snapshot is None or incoming) and "PASS ARM parent KVM frontend loaded and negotiated Linux ABI" not in log.read_text(errors="replace"):
            raise RuntimeError(f"ARM frontend probe failed; see {log}")



if __name__ == "__main__":
    main()
