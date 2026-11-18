#!/usr/bin/env python3
"""Verify the ARM TCG worker can execute directly from sealed shared pages."""
import argparse
from contextlib import ExitStack
import fcntl
import os
from pathlib import Path
import runpy
import socket
import struct
import subprocess
import tempfile
import time

QMP = runpy.run_path(str(Path(__file__).resolve().with_name("software-boot.py")))["QMP"]
PAGE = 4096
BASE = 0x80000000
# The program reads and increments a value on its second page, copies it to
# its third page, and stays running so the parent can observe the writes.
PROGRAM = struct.pack("<6I", 0x10000000, 0xb9500001, 0x11000421, 0xb9100001, 0xb9200001, 0x14000000)
SIZE_SEALS = fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def memfd(resources, name, size):
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    resources.callback(os.close, fd)
    os.ftruncate(fd, size)
    return fd


def exercise(qemu):
    with ExitStack() as resources:
        ram = memfd(resources, "arm-slot-ram", 8 * PAGE)
        layout = memfd(resources, "arm-slot-layout", 3 * 8)
        offsets = (5 * PAGE, PAGE, 6 * PAGE)
        os.pwrite(layout, struct.pack("<3Q", *offsets), 0)
        fcntl.fcntl(ram, fcntl.F_ADD_SEALS, SIZE_SEALS)
        fcntl.fcntl(layout, fcntl.F_ADD_SEALS, SIZE_SEALS | fcntl.F_SEAL_WRITE)
        os.pwrite(ram, PROGRAM, offsets[0])
        os.pwrite(ram, struct.pack("<I", 41), offsets[1])

        def command(address):
            return [
                qemu, "-machine", "virt", "-accel", "tcg", "-cpu", "cortex-a72", "-m", "16",
                "-nodefaults", "-display", "none", "-serial", "none", "-monitor", "none", "-S",
                "-device", f"flexvm-shared-ram,ram-fd={ram},layout-fd={layout},addr={address}",
            ]

        for address, reason in (
            (0x09000000, b"needs a page-aligned guest RAM address"),
            (0xbffff000, b"crosses the guest RAM aperture"),
        ):
            rejected = subprocess.run(command(address), pass_fds=(ram, layout), capture_output=True, timeout=5)
            if not rejected.returncode or reason not in rejected.stderr:
                raise RuntimeError(f"unexpected outcome for slot at {address:#x}: {rejected.stderr!r}")

        tmp = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="flexvm-arm-slot-")))
        socket = tmp / "qmp"
        with (tmp / "engine.log").open("w+b") as log:
            proc = subprocess.Popen([*command(BASE), "-device", f"loader,addr={BASE},cpu-num=0",
                                     "-qmp", f"unix:{socket},server=on,wait=off"],
                                    stdout=log, stderr=log, pass_fds=(ram, layout))
            try:
                monitor = QMP(socket, proc, time.monotonic() + 10)
                try:
                    monitor.ask("cont")
                    expected = struct.pack("<I", 42)
                    # Check the last write before reading the first, which the
                    # guest program stores earlier in the same instruction stream.
                    while os.pread(ram, 4, offsets[2]) != expected:
                        if proc.poll() is not None:
                            raise RuntimeError("ARM worker exited before updating its shared RAM")
                        time.sleep(min(0.01, monitor.remaining()))
                    if os.pread(ram, 4, offsets[1]) != expected or os.pread(ram, 4, 2 * PAGE) != bytes(4):
                        raise RuntimeError("ARM worker updated the wrong backing offsets")
                    monitor.ask("quit")
                finally:
                    monitor.close()
                if proc.wait(timeout=5) != 0:
                    raise RuntimeError("ARM worker exited with an error")
            except BaseException:
                log.seek(0)
                print(log.read().decode(errors="replace"))
                raise
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()


def exercise_mmio(qemu):
    with ExitStack() as resources:
        ram = memfd(resources, "arm-mmio-ram", PAGE)
        layout = memfd(resources, "arm-mmio-layout", 8)
        # The child reads MMIO+4, stores the value in shared RAM, writes it
        # back to MMIO+8, then spins until the parent cancels its run.
        program = struct.pack("<6I", 0x10000000, 0xd2a16002, 0xb9400441,
                              0xb9010001, 0xb9000841, 0x14000000)
        os.pwrite(ram, program, 0)
        fcntl.fcntl(ram, fcntl.F_ADD_SEALS, SIZE_SEALS)
        fcntl.fcntl(layout, fcntl.F_ADD_SEALS, SIZE_SEALS | fcntl.F_SEAL_WRITE)
        tmp = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="flexvm-arm-mmio-")))
        listener = resources.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        listener.bind(str(tmp / "run"))
        listener.listen(1)
        listener.settimeout(5)
        log = resources.enter_context((tmp / "engine.log").open("w+b"))
        mmio = 0x0b000000
        proc = subprocess.Popen([
            qemu, "-machine", "virt", "-accel", "tcg", "-cpu", "cortex-a72", "-m", "16",
            "-nodefaults", "-display", "none", "-serial", "none", "-monitor", "none", "-S",
            "-device", f"flexvm-shared-ram,ram-fd={ram},layout-fd={layout},addr={BASE}",
            "-device", f"loader,addr={BASE},cpu-num=0",
            "-chardev", f"socket,id=run,path={tmp / 'run'}",
            "-device", f"flexvm-mmio-run,chardev=run,addr={mmio}",
        ], stdout=log, stderr=log, pass_fds=(ram, layout))
        try:
            connection = resources.enter_context(listener.accept()[0])
            connection.settimeout(5)
            stream = resources.enter_context(connection.makefile("rb"))

            def expect(packet):
                received = stream.read(len(packet))
                if received != packet:
                    raise RuntimeError(f"expected {packet.hex()}, received {received.hex()}")

            expect(b"R")
            connection.sendall(b"R")
            expect(struct.pack("<cBQQ", b"Q", 4, mmio + 4, 0))
            data = struct.pack("<I", 0x12345678)
            connection.sendall(b"E" + data)
            expect(b"E")
            if os.pread(ram, 4, 256) != bytes(4):
                raise RuntimeError("read completion executed another guest instruction")
            connection.sendall(b"R")
            expect(struct.pack("<cBQQ", b"M", 4, mmio + 8, 0x12345678))
            if os.pread(ram, 4, 256) != data:
                raise RuntimeError("the child did not store the completed read")
            connection.sendall(b"R" + b"I")
            expect(b"I\0")
        except BaseException:
            log.seek(0)
            print(log.read().decode(errors="replace"))
            raise
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--mmio-run", action="store_true")
    args = parser.parse_args()
    qemu = args.qemu.resolve(strict=True)
    exercise(qemu)
    print("PASS ARM TCG reads and writes discontiguous shared RAM")
    if args.mmio_run:
        exercise_mmio(qemu)
        print("PASS ARM TCG MMIO exits, read completion and run cancellation")
