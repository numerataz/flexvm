#!/usr/bin/env python3
"""Run released ARM Firecracker through FlexVM's owned KVM device."""
import argparse
from contextlib import ExitStack
import json
import re
from pathlib import Path
import runpy
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / "software-boot.py"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "bundle", "firecracker", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--bin", type=Path, help="start the ARM provider through the public FlexVM software command")
    parser.add_argument("--engine", choices=("auto", "tcg", "kvm"), default="kvm")
    parser.add_argument("--vcpus", type=int, choices=(1, 2), default=2)
    parser.add_argument("--cc", default="cc")
    checkpoint = parser.add_mutually_exclusive_group()
    checkpoint.add_argument("--freeze", action="store_true", help="freeze and thaw the direct ARM TCG run lanes")
    checkpoint.add_argument("--transfer", action="store_true", help="retire and restore the ARM parent and its nested worker")
    checkpoint.add_argument("--pause", action="store_true", help="pause and resume both VMs through the public command")
    checkpoint.add_argument("--rollback", action="store_true", help="resume the source after aborting a completed capture")
    checkpoint.add_argument("--suspend", action="store_true", help="stop and restore both VMs through the public command")
    checkpoint.add_argument("--idle-transfer", action="store_true", help="restore before creating a nested ARM worker")
    args = parser.parse_args()
    checkpoint_test = args.freeze or args.transfer or args.rollback
    if (checkpoint_test or args.idle_transfer) and (args.bin or args.engine != "tcg"):
        parser.error("checkpoint tests require the standalone ARM TCG broker")
    public_checkpoint = args.pause or args.suspend
    if public_checkpoint and (not args.bin or args.engine != "tcg"):
        parser.error("--pause and --suspend need the public ARM TCG command")
    if args.engine == "auto" and not args.bin:
        parser.error("--engine auto requires --bin")
    output = args.output.resolve()
    output.mkdir()
    cc = [args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static"]
    outer, inner = output / "outer-init", output / "inner-init"
    mode = ["-DFLEXVM_ARM_FIRECRACKER_APP"] if args.bin else []
    if args.idle_transfer:
        mode.append("-DFLEXVM_ARM_TEST_IDLE_CHECKPOINT")
    HELPERS["run"]([*cc, *mode, ROOT / "parent-kvm/arm-firecracker-init.c", "-o", outer], 30, output / "outer-build.log")
    inner_flags = [f"-DFLEXVM_ARM_TEST_CPUS={args.vcpus}"]
    if checkpoint_test or public_checkpoint:
        inner_flags.append("-DFLEXVM_ARM_TEST_CHECKPOINT")
    HELPERS["run"]([*cc, *inner_flags, ROOT / "parent-kvm/arm-block-init.c", "-o", inner],
                   30, output / "inner-build.log")
    kernel = args.kernel.resolve(strict=True)
    config = {
        "boot-source": {"kernel_image_path": "/inner-kernel", "initrd_path": "/inner.cpio",
                        "boot_args": "console=ttyS0 quiet panic=1 rdinit=/init"},
        "machine-config": {"vcpu_count": args.vcpus, "mem_size_mib": 128},
        "drives": [{"drive_id": "blk", "path_on_host": "/tmp/drive", "is_root_device": False, "is_read_only": False}],
    }
    files = {
        "firecracker": args.firecracker.read_bytes(),
        "firecracker.json": json.dumps(config).encode(),
        "inner.cpio": HELPERS["initramfs"](inner.read_bytes()),
        "inner-kernel": kernel.read_bytes(),
    }
    log = output / "guest.log"
    if args.bin:
        image = runpy.run_path(str(ROOT / "software-kvm.py"))["image"]
        archive = output / "image.tar"
        image(archive, "arm64", {
            **{name: (data, 0o755 if name == "firecracker" else 0o600) for name, data in files.items()},
            "kvm-workload": (outer.read_bytes(), 0o755),
            "etc/passwd": (b"root:x:0:0:root:/root:/bin/sh\n", 0o644),
            "etc/group": (b"root:x:0:\n", 0o644),
        })
        with tempfile.TemporaryDirectory(prefix="flexvm-arm-parent-", dir="/var/lib") as state:
            binary = args.bin.resolve(strict=True)
            command = [
                binary, "software", "--kernel", kernel, "--qemu", args.qemu, "--state", state,
                "--parent-kvm-bundle", args.bundle, "--parent-kvm-engine", args.engine, "--parent-kvm-mem", "128",
                "--mem", "512",
            ]
            during = None
            if args.pause:
                command.extend(["--name", "arm-kvm-pause", "--verbose"])
                during = lambda proc, deadline: pause_public(proc, deadline, log, binary, state, output)
            if args.suspend:
                suspend_public(command, archive, binary, state, output, log)
            else:
                HELPERS["run"]([*command, archive], 180, log, during=during)
    else:
        cpio = output / "initramfs"
        files["flexvm-pvkvm.ko"] = (args.bundle / "flexvm-pvkvm.ko").read_bytes()
        files["tmp/drive"] = b"ARM outer persistent marker\0".ljust(1 << 20, b"\0")
        cpio.write_bytes(HELPERS["initramfs"](outer.read_bytes(), files=files))
        options = ["--tcg"] if args.engine == "tcg" else ["--worker", args.bundle / "native-worker"]
        command = [
            sys.executable, ROOT / "arm-parent-run.py", "--qemu", args.qemu, "--kernel", kernel,
            "--initrd", cpio, "--mem", "384", *options,
        ]
        if args.transfer or args.rollback or args.idle_transfer:
            transfer_checkpoint(command, output, log, rollback=args.rollback, idle=args.idle_transfer)
        elif args.freeze:
            with tempfile.TemporaryDirectory(prefix="flexvm-arm-freeze-") as directory:
                runtime = Path(directory) / "parent"
                command.extend(["--checkpoint-control", runtime])
                HELPERS["run"](command, 180, log,
                               during=lambda proc, deadline: freeze_and_thaw(proc, deadline, runtime, log))
        else:
            HELPERS["run"](command, 180, log)
    lines = log.read_text(errors="replace").splitlines()
    markers = (
        *(f"FLEXVM_ARM_INNER_CPU {cpu}" for cpu in range(args.vcpus)),
        "PASS ARM Firecracker virtio block read, write and flush",
        "PASS ARM Firecracker architected timer",
        "PASS stock ARM Firecracker used the parent-owned KVM device",
    )
    if checkpoint_test or public_checkpoint:
        markers += ("PASS ARM Firecracker resumed after checkpoint freeze",)
        before = [line.rsplit(" ", 1)[-1] for line in lines if line.startswith("ARM Firecracker checkpoint canary ")]
        after = [line.rsplit(" ", 1)[-1] for line in lines if line.startswith("ARM Firecracker restored canary ")]
        if len(before) != 1 or before != after or not re.fullmatch("[0-9a-f]{16}", before[0]):
            raise RuntimeError(f"ARM checkpoint lost the guest's memory canary; see {log}")
    for marker in markers:
        if lines.count(marker) != 1:
            raise RuntimeError(f"missing or repeated {marker}; see {log}")
    report = {"status": "passed", "nested_vcpus": args.vcpus, "parent_engine": args.engine,
              "checkpoint": next((mode for mode in ("transfer", "freeze", "rollback", "pause", "suspend", "idle_transfer") if getattr(args, mode)), None),
              "virtio_block": "read-write-flush",
              "arm_timer": "passed", "firecracker_sha256": HELPERS["digest"](args.firecracker)}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS stock ARM Firecracker executes through the parent KVM device")


def wait_checkpoint_window(proc, deadline, log, marker="ARM Firecracker checkpoint window"):
    while marker not in log.read_text(errors="replace"):
        if proc.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError("ARM nested guest did not enter the checkpoint window")
        time.sleep(.01)


def connect_checkpoint(control, proc, deadline, runtime):
    control.settimeout(min(15, deadline - time.monotonic()))
    while True:
        try:
            control.connect(str(runtime / "checkpoint"))
            return
        except (FileNotFoundError, ConnectionRefusedError):
            if proc.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("ARM checkpoint control did not become accessible")
            time.sleep(.01)


def checkpoint_request(control, request, fds=()):
    if fds:
        socket.send_fds(control, [request], fds)
    else:
        control.sendall(request)
    reply = control.recv(64)
    if reply != b"ok":
        raise RuntimeError(f"ARM checkpoint control refused {request!r}: {reply!r}")


def freeze_and_thaw(proc, deadline, runtime, log):
    wait_checkpoint_window(proc, deadline, log)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as control:
        connect_checkpoint(control, proc, deadline, runtime)
        checkpoint_request(control, b"freeze")
        time.sleep(6)
        if proc.poll() is not None or "PASS ARM Firecracker resumed after checkpoint freeze" in log.read_text(errors="replace"):
            raise RuntimeError("the nested guest advanced while its vCPUs were fenced")
        checkpoint_request(control, b"thaw")


def pause_public(proc, deadline, log, binary, state, output):
    wait_checkpoint_window(proc, deadline, log)
    HELPERS["run"]([binary, "pause", "--state", state, "arm-kvm-pause"], 15, output / "pause.log")
    hold = log.read_text(errors="replace").rsplit("ARM Firecracker checkpoint window", 1)[-1]
    if "software: parent KVM vCPUs quiesced" not in hold:
        raise RuntimeError("the public command did not fence the nested vCPUs")
    time.sleep(6)
    if proc.poll() is not None or "PASS ARM Firecracker resumed after checkpoint freeze" in log.read_text(errors="replace"):
        raise RuntimeError("the nested guest advanced while the outer FlexVM was paused")
    HELPERS["run"]([binary, "unpause", "--state", state, "arm-kvm-pause"], 15, output / "unpause.log")


def suspend_public(command, image, binary, state, output, log):
    name = "arm-kvm-checkpoint"
    source, target = output / "source.log", output / "target.log"

    def stop(proc, deadline):
        wait_checkpoint_window(proc, deadline, source)
        HELPERS["run"]([binary, "stop", "--state", state, name], 90, output / "stop.log")

    try:
        HELPERS["run"]([*command, "--name", name, "--verbose", image], 210, source, during=stop)
        checkpoint = Path(state) / "suspended" / name
        manifest = json.loads((checkpoint / "manifest.json").read_text())
        if not (checkpoint / "RETIRED").is_file() or manifest["parent"]["child_memory_mib"] != 128:
            raise RuntimeError("the public command did not publish a retired ARM hierarchy")
        for member in ("frontend", "worker", "broker"):
            if (checkpoint / f"parent-{member}").stat().st_size != manifest["parent"][member]["bytes"]:
                raise RuntimeError(f"missing ARM checkpoint {member} artifact")
        HELPERS["run"]([binary, "start", "-a", "--state", state, name], 150, target)
    finally:
        log.write_bytes(b"".join(part.read_bytes() for part in (source, target) if part.exists()))


def resume_outer(proc, deadline, runtime):
    monitor = HELPERS["QMP"](runtime / "outer-qmp", proc, deadline)
    try:
        monitor.ask("cont")
    finally:
        monitor.close()


def transfer_checkpoint(command, output, log, *, rollback=False, idle=False):
    checkpoint_window = "ARM checkpoint window before opening the nested VM" if idle else "ARM Firecracker checkpoint window"
    with ExitStack() as resources:
        root = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="flexvm-arm-transfer-")))
        source, target = root / "source", root / "target"
        source_log, target_log = output / "source.log", output / "target.log"
        files = [resources.enter_context(tempfile.TemporaryFile()) for _ in range(3)]
        fds = tuple(file.fileno() for file in files)

        def capture(proc, deadline):
            wait_checkpoint_window(proc, deadline, source_log, checkpoint_window)
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as control:
                connect_checkpoint(control, proc, deadline, source)
                checkpoint_request(control, b"freeze")
                checkpoint_request(control, b"save", fds)
                if rollback:
                    checkpoint_request(control, b"rollback")
                    resume_outer(proc, deadline, source)
                else:
                    control.sendall(b"retire")
                    if control.recv(64):
                        raise RuntimeError("source did not retire after capture")

        HELPERS["run"]([*command, "--checkpoint-control", source], 90, source_log, during=capture)
        if rollback:
            log.write_bytes(source_log.read_bytes())
            return
        for file in files:
            file.seek(0)
        if idle:
            record = json.load(files[2])
            files[2].seek(0)
            if record["worker"] is not None:
                raise RuntimeError("idle transfer captured an initialized nested worker")
        if "PASS ARM Firecracker resumed" in source_log.read_text(errors="replace"):
            raise RuntimeError("the source resumed after capture")

        def resume(proc, deadline):
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as control:
                connect_checkpoint(control, proc, deadline, target)
                checkpoint_request(control, b"thaw")
                resume_outer(proc, deadline, target)

        HELPERS["run"]([*command, "--checkpoint-control", target, "--restore-fds", *map(str, fds)],
                       90, target_log, during=resume, pass_fds=fds)
        log.write_bytes(source_log.read_bytes() + target_log.read_bytes())


if __name__ == "__main__":
    main()
