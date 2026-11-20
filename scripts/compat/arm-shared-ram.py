#!/usr/bin/env python3
"""Verify the ARM TCG worker can execute directly from sealed shared pages."""
import argparse
from contextlib import contextmanager, ExitStack
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


MMIO = 0x0b000000


def expect(stream, packet):
    received = stream.read(len(packet))
    if received != packet:
        raise RuntimeError(f"expected {packet.hex()}, received {received.hex()}")


@contextmanager
def mmio_worker(qemu, program, cpu_count, *, monitor=False, mmio=MMIO, mmio_size=PAGE):
    with ExitStack() as resources:
        ram = memfd(resources, "arm-mmio-ram", PAGE)
        layout = memfd(resources, "arm-mmio-layout", 8)
        os.pwrite(ram, program, 0)
        fcntl.fcntl(ram, fcntl.F_ADD_SEALS, SIZE_SEALS)
        fcntl.fcntl(layout, fcntl.F_ADD_SEALS, SIZE_SEALS | fcntl.F_SEAL_WRITE)
        tmp = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="flexvm-arm-mmio-")))
        listeners = []
        command = [
            qemu, "-machine", "virt,gic-version=3", "-accel", "tcg,thread=multi", "-cpu", "cortex-a72",
            "-m", "16", "-smp", str(cpu_count), "-nodefaults", "-display", "none", "-serial", "none",
            "-monitor", "none", "-S", "-device", f"flexvm-shared-ram,ram-fd={ram},layout-fd={layout},addr={BASE}",
        ]
        if not monitor:
            command.extend(["-device", f"loader,addr={BASE},cpu-num=0"])
        for cpu in range(cpu_count):
            listener = resources.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
            path = tmp / f"run{cpu}"
            listener.bind(str(path))
            listener.listen(1)
            listener.settimeout(5)
            listeners.append(listener)
            command.extend(["-chardev", f"socket,id=run{cpu},path={path}"])
        if monitor:
            command.extend(["-qmp", f"unix:{tmp / 'qmp'},server=on,wait=off"])
        second = ",parallel-chardev=run1" if cpu_count == 2 else ""
        command.extend(["-device", f"flexvm-mmio-run,chardev=run0,addr={mmio},size={mmio_size}{second}"])
        log = resources.enter_context((tmp / "engine.log").open("w+b"))
        proc = subprocess.Popen(command, stdout=log, stderr=log, pass_fds=(ram, layout))
        try:
            connections = []
            streams = []
            for listener in listeners:
                connection = resources.enter_context(listener.accept()[0])
                connection.settimeout(5)
                stream = resources.enter_context(connection.makefile("rb"))
                expect(stream, b"R")
                connections.append(connection)
                streams.append(stream)
            qmp = QMP(tmp / "qmp", proc, time.monotonic() + 10) if monitor else None
            if qmp is not None:
                resources.callback(qmp.close)
            yield ram, connections, streams, qmp
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


def exercise_mmio(qemu):
    # Read MMIO+4, store the value in shared RAM, write it to MMIO+8, then spin.
    program = struct.pack("<6I", 0x10000000, 0xd2a16002, 0xb9400441,
                          0xb9010001, 0xb9000841, 0x14000000)
    with mmio_worker(qemu, program, 1) as (ram, [connection], [stream], _):
        connection.sendall(b"R")
        expect(stream, struct.pack("<cBQQ", b"Q", 4, MMIO + 4, 0))
        data = struct.pack("<I", 0x12345678)
        connection.sendall(b"E" + data)
        expect(stream, b"E")
        if os.pread(ram, 4, 256) != bytes(4):
            raise RuntimeError("read completion executed another guest instruction")
        connection.sendall(b"R")
        expect(stream, struct.pack("<cBQQ", b"M", 4, MMIO + 8, 0x12345678))
        if os.pread(ram, 4, 256) != data:
            raise RuntimeError("the child did not store the completed read")
        connection.sendall(b"RI")
        expect(stream, b"I\0")


def exercise_parallel_mmio(qemu):
    # CPU 0 starts CPU 1 via PSCI and waits on shared RAM. CPU 1 writes the
    # shared marker. Both CPUs report it at separate MMIO offsets.
    program = struct.pack(
        "<20I",
        0x10000004, 0xd2a16005, 0x10000162, 0xd2800021, 0xd2800060,
        0xf2b88000, 0xd4000002, 0xb9010080, 0x91041086, 0x88dffcc7,
        0x34ffffe7, 0xb90004a7, 0x14000000, 0x10fffe64, 0xd2a16005,
        0x52930ec7, 0x91041086, 0x889ffcc7, 0xb90008a7, 0x14000000,
    )
    with mmio_worker(qemu, program, 2) as (ram, [first, second], [first_reply, second_reply], _):
        os.pwrite(ram, b"\xff" * 4, 256)
        first.sendall(b"R")
        deadline = time.monotonic() + 5
        while os.pread(ram, 4, 256) != bytes(4):
            if time.monotonic() >= deadline:
                raise RuntimeError("PSCI failed to start the second ARM vCPU")
            time.sleep(.01)
        second.sendall(b"S")
        expect(first_reply, struct.pack("<cBQQ", b"M", 4, MMIO + 4, 0x9876))
        expect(second_reply, struct.pack("<cBQQ", b"M", 4, MMIO + 8, 0x9876))
        first.sendall(b"RI")
        second.sendall(b"SI")
        expect(first_reply, b"I\0")
        expect(second_reply, b"I\0")


def exercise_vgic(qemu, program):
    aperture = 0x40000000
    with mmio_worker(qemu, program, 1, monitor=True, mmio=aperture, mmio_size=2 * PAGE) as (
        ram, [connection], [stream], qmp
    ):
        addresses = {"distributor": 0x3fff0000, "redistributor": 0x3ffd0000, "its": 0x3ffb0000}
        for bad in ({"distributor": addresses["its"]}, {"its": 0x3fff0001}, {"its": 0x40000000}):
            try:
                qmp.ask("x-flexvm-map-arm-gic", addresses | bad)
            except RuntimeError as error:
                if "invalid FlexVM GIC mapping" not in str(error):
                    raise
            else:
                raise RuntimeError("QEMU accepted an invalid GIC mapping")
        qmp.ask("x-flexvm-map-arm-gic", addresses)
        boot = {"cpu-index": 0, "pc": BASE, "x0": 0x1122334455667788, "pstate": 0x3c5}
        for bad in ({"cpu-index": 1}, {"pc": BASE + 2}, {"pstate": 0x3c9}):
            try:
                qmp.ask("x-flexvm-set-arm-boot-registers", boot | bad)
            except RuntimeError as error:
                if "FlexVM ARM" not in str(error):
                    raise
            else:
                raise RuntimeError("QEMU accepted invalid ARM boot registers")
        qmp.ask("x-flexvm-set-arm-boot-registers", boot)
        connection.sendall(b"R")
        expect(stream, struct.pack("<cBQQ", b"M", 4, aperture + PAGE + 4, 0))
        if os.pread(ram, 8, 272) != struct.pack("<Q", boot["x0"]):
            raise RuntimeError("the ARM vCPU did not receive the boot argument")
        revisions = struct.unpack("<3I", os.pread(ram, 12, 256))
        if any(revision & 0xf0 != 0x30 for revision in revisions):
            raise RuntimeError(f"unexpected GICD, GICR and ITS architecture revisions: {revisions}")
        connection.sendall(b"R")
        qmp.ask("x-flexvm-pulse-arm-gsi", {"gsi": 3})
        expect(stream, struct.pack("<cBQQ", b"M", 4, aperture + PAGE + 8, 35))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--mmio-run", action="store_true")
    parser.add_argument("--vgic-program", type=Path)
    args = parser.parse_args()
    qemu = args.qemu.resolve(strict=True)
    exercise(qemu)
    print("PASS ARM TCG reads and writes discontiguous shared RAM")
    if args.mmio_run:
        exercise_mmio(qemu)
        print("PASS ARM TCG MMIO exits, read completion and run cancellation")
        exercise_parallel_mmio(qemu)
        print("PASS ARM TCG vCPUs run concurrently and report independent MMIO exits")
    if args.vgic_program:
        exercise_vgic(qemu, args.vgic_program.read_bytes())
        print("PASS ARM TCG guest received an interrupt through the remapped GICv3")
