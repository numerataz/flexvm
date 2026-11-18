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
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir()
    init = output / "init"
    HELPERS["run"]([args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                    ROOT / "parent-kvm/arm-frontend-probe.c", "-o", init], 30, output / "build.log")
    module = (args.bundle / "flexvm-pvkvm.ko").read_bytes()
    cpio = output / "initramfs"
    cpio.write_bytes(HELPERS["initramfs"](init.read_bytes(), files={"flexvm-pvkvm.ko": module}))

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

        command = [
            args.qemu.resolve(strict=True), "-machine", "virt,gic-version=3", "-accel", "tcg,thread=multi",
            "-cpu", "cortex-a72", "-m", "256", "-smp", "1", "-display", "none", "-monitor", "none",
            "-serial", "none", "-nodefaults", "-nic", "none", "-no-reboot",
            "-chardev", "stdio,id=console,signal=off", "-device", "virtio-serial-device,id=serial",
            "-device", "virtconsole,chardev=console,bus=serial.0", "-kernel", args.kernel.resolve(strict=True),
            "-initrd", cpio, "-append", "console=hvc0 quiet panic=1 rdinit=/init",
            "-chardev", f"socket,id=doorbell,path={doorbell}", "-device", "ivshmem-doorbell,chardev=doorbell,vectors=2",
        ]

        def verify_handshake(proc, deadline):
            resources.enter_context(PARENT["doorbell_peer"](server, memory, requests, cancellations, (), replies))
            exited = os.pidfd_open(proc.pid)
            resources.callback(os.close, exited)
            for expected in (PARENT["OPEN_VM"], PARENT["CLOSE_VM"]):
                ready, _, _ = select.select([requests, exited], [], [], max(0, deadline - time.monotonic()))
                if requests not in ready or os.eventfd_read(requests) != 1:
                    raise RuntimeError(f"ARM probe did not send expected request {expected}")
                pending, complete, command = struct.unpack_from("<III", mailbox, 8)
                if pending != complete + 1 or command != expected:
                    raise RuntimeError(f"unexpected ARM request {command}")
                if command == PARENT["OPEN_VM"] and struct.unpack_from("<Q", mailbox, 0x89140) != (48,):
                    raise RuntimeError("ARM VM request did not preserve the IPA size")
                struct.pack_into("<i", mailbox, 20, 0)
                struct.pack_into("<I", mailbox, 12, pending)
                os.eventfd_write(replies, 1)

        log = output / "guest.log"
        HELPERS["run"](command, 45, log, during=verify_handshake)
        if "PASS ARM parent KVM frontend loaded and negotiated Linux ABI" not in log.read_text(errors="replace"):
            raise RuntimeError(f"ARM frontend probe failed; see {log}")
    print("PASS ARM parent KVM frontend handshake")


if __name__ == "__main__":
    main()
