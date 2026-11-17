#!/usr/bin/env python3
"""Verify routed TCP and UDP across a fresh software VM owner."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import signal
import socket
import subprocess as sp
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / "software-boot.py"))
IMAGE = runpy.run_path(str(ROOT / "software-kvm.py"))["image"]
PORT = 28143
PREFIX = ipaddress.IPv6Network("2001:db8:0:1::/96")


def exercise(binary, kernel, output, root, engine, arch):
    probe = output / "probe"
    IMAGE(output / "app.tar", "amd64" if arch == "x86_64" else "arm64",
          {"routed-probe": (probe.read_bytes(), 0o755)}, ["/routed-probe"])
    started = time.monotonic()
    state = root / "state"
    state.mkdir()
    config = {"vm_ips": "192.0.2.60-192.0.2.61", "announce_dev": "none", "vm_ipv6_prefix": str(PREFIX)}
    (state / "host.json").write_text(json.dumps(config))
    cli = [binary, "--state", state, "--run", root / "run"]
    owners = []

    def call(*args, timeout=20):
        return sp.check_output([*cli, *args], text=True, timeout=timeout)

    def lookup(status, name):
        entries = json.loads(call("ps", "-a", "--json"))
        return next((entry for entry in entries if entry["name"] == name and entry["state"] == status), None)

    def route(addr):
        mask = "/128" if ":" in addr else "/32"
        return json.loads(sp.check_output(["ip", "-j", "route", "show", "exact", addr + mask], timeout=10))

    def launch(label, name, *args):
        with (output / f"{label}-owner.log").open("wb") as log:
            process = sp.Popen([*cli, *args], stdout=log, stderr=log)
        owners.append(process)
        until = time.monotonic()+90
        while process.poll() is None and time.monotonic() < until:
            if entry := lookup("running", name):
                return process, entry
            time.sleep(.1)
        raise RuntimeError(f'{label} failed readiness')

    def removed(addr, addr6, dev):
        until = time.monotonic()+12
        while (route(addr) or route(addr6)) and time.monotonic() < until:
            time.sleep(.1)
        assert not route(addr) and not route(addr6), (route(addr), route(addr6))
        interfaces = json.loads(sp.check_output(['ip', '-j', 'link', 'show'], timeout=10))
        assert all(entry['ifname'] != dev for entry in interfaces), interfaces

    def tcp_echo(sock, payload):
        sock.sendall(payload)
        received = b''
        while len(received) < len(payload):
            part = sock.recv(4096)
            assert part, 'unexpected TCP EOF'
            received += part
        assert received == payload, received

    def udp_echo(addr, payload):
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(8)
            udp.sendto(payload, (addr, PORT))
            assert udp.recv(4096) == payload

    try:
        source, initial = launch('cold', 'routed', 'software', '--name', 'routed', '--network', 'routed', '--qemu', engine, '--kernel', kernel, output/'app.tar')
        addr = initial['ip']
        addr6 = str(ipaddress.IPv6Address(int(PREFIX.network_address) | int(ipaddress.IPv4Address(addr))))
        original_route, = route(addr)
        tap = original_route['dev']
        assert tap.startswith('fsw'), original_route
        assert route(addr6)[0]["dev"] == tap
        with socket.create_connection((addr, PORT), timeout=10) as tcp:
            tcp_echo(tcp, b'tcp-before')
            udp_echo(addr, b'udp-before')
            udp_echo(addr6, b'udp6-before')
            call('stop', 'routed', timeout=120)
            assert source.wait(timeout=15) == 0
            removed(addr, addr6, tap)
            assert lookup('suspended', 'routed')['ip'] == addr
            result = sp.run([*cli, 'software-transfer', 'offer', 'routed', '11111111111111111111111111111111'], capture_output=True, text=True, timeout=20)
            assert result.returncode != 0 and 'local restore only' in result.stderr, result.stderr
            competitor, other = launch("competitor", "competitor", "software", "--name", "competitor",
                                       "--network", "routed", "--qemu", engine, "--kernel", kernel, output / "app.tar")
            assert other["ip"] != addr, other
            resumed, after = launch("resumed", "routed", "start", "--attach", "routed")
            new_route, = route(addr)
            assert after['ip'] == addr and after['gen'] == initial['gen'] and new_route['dev'] != tap, (initial, after, new_route)
            assert route(addr6)[0]["dev"] == new_route["dev"]
            tcp_echo(tcp, b'tcp-after-on-same-socket')
            udp_echo(addr, b'udp-after')
            udp_echo(addr6, b'udp6-after')
        resumed.kill()
        assert resumed.wait(timeout=10) == -signal.SIGKILL
        removed(addr, addr6, new_route['dev'])
        call('rm', '-f', 'routed')
        competitor.send_signal(signal.SIGINT)
        competitor.wait(timeout=15)
        owned_route = route(other['ip'])
        assert not owned_route, owned_route
        bogus = sp.run([*cli, 'software', '--name', 'broken', '--network', 'routed', '--qemu', '/bin/false', '--kernel', kernel, output/'app.tar'], capture_output=True, text=True, timeout=25)
        assert bogus.returncode != 0
        assert not route(addr) and not route(other['ip']), bogus.stderr
        call('debug', 'gc')
        report = {
            "status": "passed",
            "tcp_socket_preserved": True,
            "udp_v4_v6_before_and_after": True,
            "address_held_while_stopped": True,
            "peer_transfer_refused": True,
            "owner_signal": -resumed.returncode,
            "first_tap": tap,
            "second_tap": new_route["dev"],
            "address": addr,
            "address6": addr6,
            "competing_address": other["ip"],
            "route_after_owner_death": False,
            "route_after_launch_failure": False,
            "elapsed_s": round(time.monotonic() - started, 3),
        }
        (output / "report.json").write_text(json.dumps(report) + "\n")
    finally:
        for owner in owners:
            if owner.poll() is None:
                owner.send_signal(signal.SIGINT)
                try:
                    owner.wait(timeout=7)
                except sp.TimeoutExpired:
                    owner.kill()
                    owner.wait(timeout=7)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--worker-state", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary, kernel, output = (path.resolve() for path in (args.bin, args.kernel, args.output))
    arch = platform.machine()
    engine = shutil.which("qemu-system-" + arch)
    if os.geteuid() != 0 or arch not in ("x86_64", "aarch64") or engine is None:
        parser.error("run as root with native x86_64 or aarch64 QEMU")
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be 1..3600 seconds")
    if args.worker_state:
        exercise(binary, kernel, output, args.worker_state, engine, arch)
        return 0
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    if report_path.exists():
        parser.error("use an output directory without an existing report")
    try:
        HELPERS["run"]([args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                        str(ROOT / "routed-network-probe.c"), "-o", str(output / "probe")], 60, output / "compile.log")
        trace = output / "files.strace"
        with tempfile.TemporaryDirectory(prefix="flexvm-routed-network-", dir="/var/lib") as state:
            mask = Path(state) / "mask"
            mask.touch(mode=0o600)
            setup = """
                ip link set lo up
                ip address add 198.51.100.1/32 dev lo scope global
                ip -6 address add 2001:db8:0:2::1/128 dev lo nodad
                for dev in /dev/kvm /dev/vhost-vsock /dev/vhost-net; do
                    if [ -e "$dev" ]; then mount --bind "$1" "$dev"; fi
                done
                shift
                exec "$@"
            """
            HELPERS["run"](["unshare", "--net", "--mount", "--propagation", "private", "sh", "-ec", setup,
                            "sh", str(mask), "strace", "-f", "-e", "trace=file", "-o", str(trace),
                            sys.executable, str(Path(__file__).resolve()), "--bin", str(binary), "--kernel", str(kernel),
                            "--output", str(output), "--worker-state", state], args.timeout, output / "worker.log")
        if any(f'"{dev}"' in trace.read_text(errors="replace") for dev in ("/dev/kvm", "/dev/vhost-vsock", "/dev/vhost-net")):
            raise RuntimeError("host virtualization device access; see files.strace")
        report = json.loads(report_path.read_text())
        report.update(kvm_access=False, vhost_vsock_access=False, vhost_net_access=False,
                      binary_sha256=HELPERS["digest"](binary), kernel_sha256=HELPERS["digest"](kernel))
    except Exception as error:
        report = {"status": "failed", "error": str(error)}
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}: {report_path}")
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
