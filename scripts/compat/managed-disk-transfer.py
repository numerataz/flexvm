#!/usr/bin/env python3
"""Transfer and return a stopped software VM with two writable filesystems."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import subprocess as sp
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / "software-boot.py"))
IMAGE = runpy.run_path(str(ROOT / "software-kvm.py"))["image"]


def exercise(binary, kernel, output, root):
    arch = platform.machine()
    engine = shutil.which("qemu-system-" + arch)
    if engine is None:
        raise FileNotFoundError("native QEMU is required for software disk transfer")
    host_a = [binary, "--state", root / "a", "--run", root / "a-run"]
    host_b = [binary, "--state", root / "b", "--run", root / "b-run"]
    owners = []
    started = time.monotonic()

    def cli(base, *words, fail=None, timeout=60):
        result = sp.run([*base, *words], stdout=sp.PIPE, stderr=sp.PIPE, text=True, timeout=timeout)
        if fail:
            assert result.returncode and fail in result.stderr, result
        else:
            assert result.returncode == 0, result
        return result.stdout

    def transfer(base, *words, fail=None, timeout=60):
        return cli(base, "software-transfer", *words, fail=fail, timeout=timeout)

    def key_pair(label):
        private = root / f"{label}.der"
        sp.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-outform", "DER", "-out", private], check=True, timeout=15)
        private.chmod(0o600)
        pub = sp.check_output(["openssl", "pkey", "-inform", "DER", "-in", private, "-pubout", "-outform", "DER"], timeout=15)
        return private, base64.b64encode(pub[-32:]).decode()

    def launch(base, vm, *args):
        with (output / f"{vm}-owner.log").open("wb") as log:
            owner = sp.Popen([*base, *args], stdout=log, stderr=log)
        owners.append(owner)
        until = time.monotonic() + 95
        while time.monotonic() < until and owner.poll() is None:
            if any(e["name"] == vm and e["state"] == "running" for e in json.loads(cli(base, "ps", "--json"))):
                return owner
            time.sleep(0.1)
        raise RuntimeError(f"{vm} failed to publish")

    def boot(name):
        return ("software", "--name", name, "--control", "serial", "--kernel", kernel, "--disk", "data-one", "--disk", "data-two", output / "image.tar")

    def guest(host, name):
        return [int(v) for v in cli(host, "exec", name, "/state-probe", "status").split()]

    def content(host, name, disk, expected):
        assert cli(host, "exec", name, "/disk-probe", disk, "read") == expected

    def check_progress(host, name, original):
        until = time.monotonic() + 20
        while time.monotonic() < until:
            current = guest(host, name)
            assert current[:3] == original[:3], (original, current)
            if current[3] > original[3] and current[4] > original[4]:
                return current
            time.sleep(0.15)
        raise RuntimeError("guest made no fresh progress")

    def send(sender, receiver, name, remote_name, src_key, src_pub, dst_pub, specs):
        offer_path, receipt_path = root / f"{remote_name}-offer", root / f"{remote_name}-receipt"
        dest_host = json.loads(transfer(receiver, "id"))["host_id"]
        offer_path.write_text(transfer(sender, "offer", name, dest_host))
        assert json.loads(transfer(receiver, "prepare", offer_path, "--source-key", src_pub))["status"] == "pending"
        receipt_path.write_text(transfer(sender, "retire", name, offer_path, "--signing-key", src_key, "--destination-key", dst_pub))
        for disk_id in specs:
            cli(sender, "volume", "rm", disk_id, fail="fenced by software VM transfer")
        with (output / f"{remote_name}-send.log").open("wb") as errors:
            with sp.Popen([*sender, "software-transfer", "send", name, offer_path], stdout=sp.PIPE, stderr=errors) as stream:
                try:
                    receipt = sp.check_output([*receiver, "software-transfer", "receive", offer_path], stdin=stream.stdout, timeout=90)
                    assert stream.wait(timeout=15) == 0
                finally:
                    if stream.poll() is None:
                        stream.kill()
        assert json.loads(transfer(receiver, "commit", receipt_path))["status"] == "committed"
        owner = launch(receiver, remote_name, "software-transfer", "activate", offer_path, remote_name, "--qemu", engine)
        transfer(receiver, "activate", offer_path, remote_name + "-replay", "--qemu", engine, fail="already granted")
        return owner, json.loads(receipt)["bytes"]

    try:
        image_arch = "amd64" if arch == "x86_64" else "arm64"
        IMAGE(output / "image.tar", image_arch, {"state-probe": ((output / "state-probe").read_bytes(), 0o755),
              "disk-probe": ((output / "disk-probe").read_bytes(), 0o755), "etc/passwd": (b"root:x:0:0:root:/root:/bin/sh\n", 0o644),
              "etc/group": (b"root:x:0:\n", 0o644)}, ["/state-probe"])
        specs = [json.loads(cli(host_a, "volume", "create", name, "--size", str(24 << 20)))["id"] for name in ("data-one", "data-two")]
        original_disks = [root / "a" / "volumes" / volume_id / "disk.raw" for volume_id in specs]
        for disk in original_disks:
            sp.run(["mkfs.ext4", "-q", "-F", disk], check=True, timeout=25)
        before_inodes = [disk.stat().st_ino for disk in original_disks]
        a_key, a_pub = key_pair("a")
        b_key, b_pub = key_pair("b")
        a_owner = launch(host_a, "source", *boot("source"))
        a_state = guest(host_a, "source")
        for disk, value in [("primary", "first-on-a"), ("secondary", "second-on-a")]:
            cli(host_a, "exec", "source", "/disk-probe", disk, "write", value)
        cli(host_a, "stop", "source", timeout=120)
        assert a_owner.wait(timeout=15) == 0
        b_owner, sent = send(host_a, host_b, "source", "on-peer", a_key, a_pub, b_pub, specs)
        b_state = check_progress(host_b, "on-peer", a_state)
        content(host_b, "on-peer", "primary", "first-on-a")
        content(host_b, "on-peer", "secondary", "second-on-a")
        for disk_id in specs:
            cli(host_b, "volume", "rm", disk_id, fail="still in use")
        for disk, value in [("primary", "first-on-b"), ("secondary", "second-on-b")]:
            cli(host_b, "exec", "on-peer", "/disk-probe", disk, "write", value)
        cli(host_b, "stop", "on-peer", timeout=120)
        assert b_owner.wait(timeout=15) == 0
        a_return, returned = send(host_b, host_a, "on-peer", "returned", b_key, b_pub, a_pub, specs)
        after = check_progress(host_a, "returned", b_state)
        content(host_a, "returned", "primary", "first-on-b")
        content(host_a, "returned", "secondary", "second-on-b")
        transfer(host_a, "retire", "source", root / "on-peer-offer", "--signing-key", a_key, "--destination-key", b_pub,
                 fail="already returned to this source")
        transfer(host_a, "send", "source", root / "on-peer-offer", fail="needs an exact fenced source")
        after_inodes = [disk.stat().st_ino for disk in original_disks]
        assert all(before != current for before, current in zip(before_inodes, after_inodes))
        cli(host_a, "kill", "returned")
        a_return.wait(timeout=15)
        cli(host_a, "start", "source", fail="changed since checkpoint")
        (output / "report.json").write_text(json.dumps({"status": "passed", "elapsed_s": round(time.monotonic() - started, 3),
            "outbound_bytes": sent, "return_bytes": returned, "stale_handoff_rejected": True, "disks": specs, "before": a_state, "peer": b_state, "returned": after,
            "disk_sha256": [hashlib.file_digest(disk.open("rb"), "sha256").hexdigest() for disk in original_disks]}, indent=2) + "\n")
    finally:
        for base, name in ((host_a, "source"), (host_a, "returned"), (host_b, "on-peer")):
            try:
                sp.run([*base, "rm", "-f", name], capture_output=True, timeout=10)
            except sp.TimeoutExpired:
                pass
        for owner in owners:
            if owner.poll() is None:
                owner.kill()
                owner.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--worker-state", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary, kernel, output = (p.resolve() for p in (args.bin, args.kernel, args.output))
    if args.worker_state:
        exercise(binary, kernel, output, args.worker_state)
        return 0
    if platform.machine() not in ("x86_64", "aarch64") or os.geteuid() != 0:
        parser.error("run as root on native x86_64 or aarch64")
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be 1..3600 seconds")
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    if report_path.exists():
        parser.error("use an output directory without an existing report")
    try:
        for name, source in (("state-probe", "state-probe.c"), ("disk-probe", "managed-disk-probe.c")):
            HELPERS["run"]([args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-pthread",
                            str(ROOT / source), "-o", str(output / name)], 60, output / (name + "-compile.log"))
        mask = output / "masked-device"
        mask.touch(mode=0o600)
        trace = output / "files.strace"
        with tempfile.TemporaryDirectory(prefix="flexvm-managed-disk-roundtrip-", dir="/var/lib") as state:
            HELPERS["run"](["unshare", "--mount", "--propagation", "private", "sh", "-ec",
                            'for dev in /dev/kvm /dev/vhost-vsock; do if [ -e "$dev" ]; then mount --bind "$1" "$dev"; fi; done; shift; exec "$@"',
                            "sh", str(mask), "strace", "-f", "-e", "trace=file", "-o", str(trace), sys.executable, str(Path(__file__).resolve()),
                            "--bin", str(binary), "--kernel", str(kernel), "--output", str(output), "--worker-state", state],
                           args.timeout, output / "worker.log")
        if any(f'"{dev}"' in trace.read_text(errors="replace") for dev in ("/dev/kvm", "/dev/vhost-vsock")):
            raise RuntimeError("host virtualization device access; see files.strace")
        report = json.loads(report_path.read_text())
        report.update(kvm_access=False, vhost_vsock_access=False, binary_sha256=HELPERS["digest"](binary), kernel_sha256=HELPERS["digest"](kernel))
    except Exception as error:
        report = {"status": "failed", "error": str(error)}
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}: {report_path}")
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
