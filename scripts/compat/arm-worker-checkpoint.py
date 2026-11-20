#!/usr/bin/env python3
"""Resume a stopped ARM TCG worker against parent-restored RAM."""
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

ROOT = Path(__file__).resolve().parent
TOOLS = runpy.run_path(str(ROOT / "arm-shared-ram.py"))
QMP, memfd, expect = (TOOLS[name] for name in ("QMP", "memfd", "expect"))
BASE, PAGE, MMIO = (TOOLS[name] for name in ("BASE", "PAGE", "MMIO"))
SIZE_SEALS = TOOLS["SIZE_SEALS"]
# Read 41, report it, increment the register, store to shared RAM and report 42.
PROGRAM = struct.pack("<8I", 0x10000003, 0xd2a16004, 0xb9400080, 0xb9000480,
                      0x91000400, 0xb9010060, 0xb9000880, 0x14000000)


@contextmanager
def worker(qemu, ram, offset, *, external=False, incoming=False):
    with ExitStack() as resources:
        layout = memfd(resources, "arm-checkpoint-layout", 8)
        os.pwrite(layout, struct.pack("<Q", offset), 0)
        fcntl.fcntl(layout, fcntl.F_ADD_SEALS, SIZE_SEALS | fcntl.F_SEAL_WRITE)
        tmp = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="flexvm-arm-worker-")))
        listener = resources.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        listener.bind(str(tmp / "run"))
        listener.listen(1)
        listener.settimeout(5)
        log = resources.enter_context((tmp / "engine.log").open("w+b"))
        slot = f"flexvm-shared-ram,ram-fd={ram},layout-fd={layout},addr={BASE}"
        device = f"flexvm-mmio-run,chardev=run,addr={MMIO}"
        if external:
            slot += ",external-ram-state=on"
            device += ",checkpoint-control=on"
        command = [
            qemu, "-machine", "virt,gic-version=3", "-accel", "tcg", "-cpu", "cortex-a72", "-m", "16",
            "-nodefaults", "-display", "none", "-serial", "none", "-nic", "none", "-monitor", "none", "-S",
            "-chardev", f"socket,id=run,path={tmp / 'run'}", "-device", device,
            "-qmp", f"unix:{tmp / 'qmp'},server=on,wait=off", "-device", slot,
            "-device", f"loader,addr={BASE},cpu-num=0",
        ]
        if incoming:
            command.extend(["-incoming", "defer"])
        proc = subprocess.Popen(command, stdout=log, stderr=log, pass_fds=(ram, layout))
        try:
            connection = resources.enter_context(listener.accept()[0])
            connection.settimeout(5)
            stream = resources.enter_context(connection.makefile("rb"))
            expect(stream, b"R")
            monitor = QMP(tmp / "qmp", proc, time.monotonic() + 15)
            resources.callback(monitor.close)
            yield monitor, connection, stream
        except BaseException:
            log.seek(0)
            print(log.read().decode(errors="replace"))
            raise
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()


def wait_transfer(qmp):
    while True:
        reply = qmp.ask("query-migrate")
        if reply["status"] == "completed":
            return
        if reply["status"] not in ("setup", "active", "device"):
            raise RuntimeError(f"unexpected ARM worker migration status: {reply}")
        time.sleep(min(.01, qmp.remaining()))


def exercise(qemu):
    with ExitStack() as resources:
        source = memfd(resources, "arm-source-ram", 4 * PAGE)
        destination = memfd(resources, "arm-destination-ram", 4 * PAGE)
        for ram in (source, destination):
            fcntl.fcntl(ram, fcntl.F_ADD_SEALS, SIZE_SEALS)
        source_offset, destination_offset = 2 * PAGE, PAGE
        os.pwrite(source, PROGRAM, source_offset)
        sentinel = os.urandom(32)
        os.pwrite(source, sentinel, source_offset + 512)
        with worker(qemu, source, source_offset) as (monitor, _, _):
            with tempfile.TemporaryFile() as state:
                monitor.send_fd(state.fileno())
                try:
                    monitor.ask("migrate", {"uri": "fd:snapshot"})
                except RuntimeError as error:
                    if "another worker's live RAM" not in str(error):
                        raise
                else:
                    raise RuntimeError("default shared slots allowed an uncoordinated migration")

        with tempfile.TemporaryFile() as state:
            with worker(qemu, source, source_offset, external=True) as (monitor, connection, stream):
                connection.sendall(b"R")
                expect(stream, struct.pack("<cBQQ", b"Q", 4, MMIO, 0))
                try:
                    monitor.ask("x-flexvm-freeze-run-control", {"frozen": True})
                except RuntimeError as error:
                    if "pending execution or I/O" not in str(error):
                        raise
                else:
                    raise RuntimeError("worker fenced an incomplete MMIO read")
                with tempfile.TemporaryFile() as incomplete:
                    monitor.send_fd(incomplete.fileno())
                    try:
                        monitor.ask("migrate", {"uri": "fd:snapshot"})
                    except RuntimeError as error:
                        if "run control is unfenced" not in str(error):
                            raise
                    else:
                        raise RuntimeError("worker migrated without a run-control fence")
                connection.sendall(b"E" + struct.pack("<I", 41))
                expect(stream, b"E")
                connection.sendall(b"R")
                expect(stream, struct.pack("<cBQQ", b"M", 4, MMIO + 4, 41))
                if monitor.ask("query-status")["status"] != "paused":
                    raise RuntimeError("the ARM worker is still running")
                monitor.ask("x-flexvm-freeze-run-control", {"frozen": True})
                monitor.send_fd(state.fileno())
                monitor.ask("migrate", {"uri": "fd:snapshot"})
                wait_transfer(monitor)
                os.pwrite(destination, os.pread(source, PAGE, source_offset), destination_offset)

            state.seek(0)
            if sentinel in state.read():
                raise RuntimeError("worker migration duplicated parent-owned RAM")
            state.seek(0)
            with worker(qemu, destination, destination_offset, external=True, incoming=True) as (monitor, connection, stream):
                monitor.ask("x-flexvm-freeze-run-control", {"frozen": True})
                monitor.send_fd(state.fileno())
                monitor.ask("migrate-incoming", {"uri": "fd:snapshot"})
                wait_transfer(monitor)
                if monitor.ask("query-status")["status"] != "paused":
                    raise RuntimeError("the restored worker ran before the owner's resume")
                monitor.ask("x-flexvm-freeze-run-control", {"frozen": False})
                connection.sendall(b"R")
                expect(stream, struct.pack("<cBQQ", b"M", 4, MMIO + 8, 42))
                if os.pread(destination, 4, destination_offset + 256) != struct.pack("<I", 42):
                    raise RuntimeError("restored worker did not update its new RAM backing")
                if os.pread(source, 4, source_offset + 256) != bytes(4):
                    raise RuntimeError("the old worker RAM changed after retirement")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    args = parser.parse_args()
    exercise(args.qemu.resolve(strict=True))
    print("PASS ARM worker retains live CPU state across external RAM restore")
