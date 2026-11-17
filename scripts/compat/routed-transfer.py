#!/usr/bin/env python3
"""Keep a TCP connection through a signed routed software VM round trip."""
import argparse
from contextlib import contextmanager
import base64
import os
import json
from pathlib import Path
import platform
import runpy
import selectors
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


TCP_CLIENT = """
import socket, sys
with socket.create_connection((sys.argv[1], 28143), timeout=15) as connection:
    print("connected", flush=True)
    for message in sys.stdin.buffer:
        connection.sendall(message)
        reply = bytearray()
        while len(reply) < len(message):
            part = connection.recv(4096)
            if not part:
                raise RuntimeError("TCP client reached EOF")
            reply.extend(part)
        print(reply.hex(), flush=True)
"""

UDP_CLIENT = """
import socket, sys
payload = b'one-shot-udp-during-software-checkpoint'
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
    connection.settimeout(105)
    connection.sendto(payload, (sys.argv[1], 28143))
    print("sent", flush=True)
    reply, _ = connection.recvfrom(4096)
    if reply != payload:
        raise RuntimeError(f"unexpected UDP echo: {reply!r}")
    print("received", flush=True)
"""


@contextmanager
def configured_peers(enabled, timeout):
    if not enabled:
        yield {}
        return
    namespaces = []
    try:
        for site in ("a", "b"):
            process = sp.Popen(["unshare", "--net", "sleep", str(timeout + 60)])
            namespaces.append((site, process))
            until = time.monotonic() + 5
            while (Path(f"/proc/{process.pid}/ns/net").stat().st_ino == Path("/proc/self/ns/net").stat().st_ino
                   and time.monotonic() < until):
                time.sleep(.05)
            if Path(f"/proc/{process.pid}/ns/net").stat().st_ino == Path("/proc/self/ns/net").stat().st_ino:
                raise RuntimeError(f"peer {site} did not enter its own network namespace")
        sp.run(["ip", "link", "add", "peer-a", "type", "veth", "peer", "name", "peer-b"], check=True, timeout=10)
        routes = {}
        for index, (site, process) in enumerate(namespaces, 1):
            interface = "peer-" + site
            prefix = ["nsenter", "--net", "-t", str(process.pid)]
            address = f"198.18.0.{index}"
            other = f"198.18.0.{3 - index}:7150"
            sp.run(["ip", "link", "set", interface, "netns", str(process.pid)], check=True, timeout=10)
            for words in (["ip", "link", "set", "lo", "up"], ["ip", "link", "set", interface, "up"],
                          ["ip", "address", "add", address + "/30", "dev", interface],
                          ["sysctl", "-qw", "net.ipv4.ip_forward=1"]):
                sp.run([*prefix, *words], check=True, timeout=10)
            routes[site] = (prefix, address, other)
        yield routes
    finally:
        for _, process in namespaces:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


def exercise(binary, kernel, output, engine, root, arch, network):
    probe = output / "probe"
    IMAGE(output / "fixture.tar", "amd64" if arch == "x86_64" else "arm64",
          {"routed-probe": (probe.read_bytes(), 0o755)}, ["/routed-probe"])
    started = time.monotonic()
    owners = []
    bases = {}
    for site, pool in [('a', '192.0.2.60-192.0.2.61'), ('b', '192.0.2.80-192.0.2.81')]:
        state = root / site
        state.mkdir()
        config = {"vm_ips": pool, "cluster_ips": "192.0.2.0/24", "announce_dev": "none"}
        prefix = []
        if network:
            prefix, address, other = network[site]
            config.update(listen=f"{address}:7150", underlay=address, peers=[other])
        else:
            config["vm_ipv6_prefix"] = "2001:db8:0:1::/96"
        (state / "host.json").write_text(json.dumps(config))
        bases[site] = [*prefix, binary, "--state", state, "--run", root / f"{site}-run"]
    a, b = bases['a'], bases['b']

    def cli(base, *args, timeout=30, failure=None):
        done = sp.run([*base, *args], stdout=sp.PIPE, stderr=sp.PIPE, text=True, timeout=timeout)
        if failure is None:
            assert done.returncode == 0, done.stderr
        else:
            assert done.returncode != 0 and failure in done.stderr, done.stderr
        return done.stdout

    def transfer(base, *args, **options):
        return cli(base, 'software-transfer', *args, **options)

    def key(label):
        path = root / f'{label}.der'
        sp.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-outform', 'DER', '-out', path], check=True, timeout=15)
        path.chmod(0o600)
        pub = sp.check_output(['openssl', 'pkey', '-inform', 'DER', '-in', path, '-pubout', '-outform', 'DER'], timeout=15)
        return path, base64.b64encode(pub[-32:]).decode()

    def spawn(base, label, *args):
        with (output / f"{label}.log").open("wb") as log:
            process = sp.Popen([*base, *args], stdout=log, stderr=log)
        owners.append(process)
        return process

    def launch(base, name, *args):
        proc = spawn(base, f"{name}-owner", *args)
        until = time.monotonic()+100
        while proc.poll() is None and time.monotonic() < until:
            for entry in json.loads(cli(base, 'ps', '--json')):
                if entry['name'] == name and entry['state'] == 'running':
                    return proc, entry
            time.sleep(.15)
        raise RuntimeError(f'{name} failed to publish: {proc.poll()}')

    def stop(base, name, owner):
        cli(base, 'stop', name, timeout=130)
        assert owner.wait(timeout=20) == 0

    def move(sender, receiver, name, other, src, dst):
        offer = root / f"{other}-offer"
        receipt = root / f"{other}-receipt"
        receiver_id = json.loads(transfer(receiver, "id"))["host_id"]
        offer.write_text(transfer(sender, "offer", name, receiver_id))
        proposed = json.loads(offer.read_text())
        assert json.loads(transfer(receiver, "prepare", offer, "--source-key", src[1]))["status"] == "pending"
        receipt.write_text(transfer(sender, "retire", name, offer, "--signing-key", src[0], "--destination-key", dst[1]))
        cli(sender, "start", name, failure="source cannot restart")
        with (output / f"{other}-send.log").open("wb") as log:
            with sp.Popen([*sender, "software-transfer", "send", name, offer], stdout=sp.PIPE, stderr=log) as stream:
                try:
                    received = json.loads(sp.check_output([*receiver, "software-transfer", "receive", offer], stdin=stream.stdout, timeout=95))
                    assert stream.wait(timeout=15) == 0
                finally:
                    if stream.poll() is None:
                        stream.kill()
        assert json.loads(transfer(receiver, "commit", receipt))["status"] == "committed"
        options = []
        if network:
            receiver_site = "a" if receiver is a else "b"
            options.extend(["--route-peer", network[receiver_site][2], "--signing-key", dst[0]])
        owner, entry = launch(receiver, other, "software-transfer", "activate", offer, other, "--qemu", engine, *options)
        if network:
            source_site = "a" if sender is a else "b"
            ip = proposed["routed"]["address"]["v4"]
            wanted = network[receiver_site][1]
            until = time.monotonic() + 12
            while time.monotonic() < until:
                if any(entry.get("gateway") == wanted for entry in routes(source_site, ip)):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError(f"{source_site} did not install the signed route to {wanted}")
        transfer(receiver, "activate", offer, other + "-replay", "--qemu", engine, failure="already granted")
        return owner, entry, proposed["routed"], received["bytes"]

    def routes(site, ip):
        prefix = network[site][0] if network else []
        return json.loads(sp.check_output([*prefix, "ip", "-j", "-4", "route", "show", "exact", ip + "/32"], timeout=5))

    def client_line(process):
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=20):
                raise TimeoutError("the original TCP client stopped responding")
            response = process.stdout.readline()
        if not response:
            raise RuntimeError("the original TCP client exited")
        return response.rstrip()

    @contextmanager
    def connection(ip):
        if not network:
            with socket.create_connection((ip, 28143), timeout=15) as client:
                yield client
            return
        with (output / "tcp-client.log").open("wb") as log:
            client = sp.Popen([*network["a"][0], sys.executable, "-c", TCP_CLIENT, ip],
                              stdin=sp.PIPE, stdout=sp.PIPE, stderr=log, text=True, bufsize=1)
        try:
            assert client_line(client) == "connected"
            yield client
        finally:
            client.stdin.close()
            try:
                client.wait(timeout=8)
            except sp.TimeoutExpired:
                client.kill()
                client.wait(timeout=5)
            client.stdout.close()

    def echo(tcp, message):
        if network:
            tcp.stdin.write(message.decode() + "\n")
            tcp.stdin.flush()
            assert client_line(tcp) == (message + b"\n").hex()
            return
        tcp.sendall(message)
        response = bytearray()
        while len(response) < len(message):
            chunk = tcp.recv(4096)
            assert chunk, message
            response.extend(chunk)
        assert response == message, response

    def addr_record(site, ip):
        return json.loads((root/site/'addrs'/ip).read_text())

    def hold_route(label, timeout=150):
        with (output / (label + ".log")).open("wb") as log:
            process = sp.Popen([*a, "software-transfer", "hold-route", "source", "--timeout", str(timeout)],
                               stdout=sp.PIPE, stderr=log, text=True, bufsize=1)
        owners.append(process)
        assert json.loads(client_line(process))["status"] == "holding"
        return process

    try:
        if network:
            for site, peer in bases.items():
                spawn(peer, site + "-listener", "listen")
            until = time.monotonic() + 12
            for site in ("a", "b"):
                prefix, address, other = network[site]
                while time.monotonic() < until:
                    probe = sp.run([*prefix, sys.executable, "-c",
                                    "import socket,sys; socket.create_connection((sys.argv[1], 7150), 1).close()",
                                    other.rsplit(":", 1)[0]], capture_output=True, timeout=3)
                    if probe.returncode == 0:
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError(f"peer listener was not reachable from {address}")
        a_key, b_key = key('a'), key('b')
        first, initial = launch(a,'source','software','--name','source','--network','routed','--qemu',engine,'--kernel',kernel,output/'fixture.tar')
        ip = initial['ip']
        held_packets = None
        with connection(ip) as tcp:
            echo(tcp,b'routed-connection-before-transfer')
            if network:
                cancelled = hold_route("hold-cancelled", timeout=1)
                assert json.loads(client_line(cancelled))["status"] == "restored-source"
                assert cancelled.wait(timeout=5) == 0
                cancelled.stdout.close()
                echo(tcp,b'routed-connection-after-hold-expiry')
                hold = hold_route("hold-outbound")
            stop(a,'source',first)
            if network:
                with (output / "udp-client.log").open("wb") as log:
                    udp = sp.Popen([*network["a"][0], sys.executable, "-c", UDP_CLIENT, ip],
                                   stdout=sp.PIPE, stderr=log, text=True, bufsize=1)
                owners.append(udp)
                assert client_line(udp) == "sent"
            peer, moved, outbound, sent = move(a,b,'source','peer',a_key,b_key)
            if network:
                held = json.loads(client_line(hold))
                assert held["status"] == "forwarded", held
                held_packets = held["hold"]
                assert held_packets["packets"] >= 1 and held_packets["dropped"] == 0, held
                assert client_line(udp) == "received"
                assert udp.wait(timeout=5) == 0 and hold.wait(timeout=5) == 0
                udp.stdout.close()
                hold.stdout.close()
            assert moved['ip'] == ip and moved['gen'] == initial['gen']
            assert addr_record('a',ip)['lent'] == outbound['generation']
            echo(tcp,b'same-routed-connection-on-peer')
            cli(a,'rm','-f','source')
            assert addr_record('a',ip)['lent'] == outbound['generation'], 'discard released active remote address'
            stop(b,'peer',peer)
            returned, after, inbound, back = move(b,a,'peer','returned',b_key,a_key)
            assert after['ip'] == ip and after['gen'] == initial['gen']
            assert outbound['address'] == inbound['address'] and outbound['generation'] == inbound['generation']
            assert inbound['revision'] > outbound['revision']
            assert addr_record('a',ip)['lent'] is None
            echo(tcp,b'same-routed-connection-returned')
        cli(a,'rm','-f','returned')
        returned.wait(timeout=12)
        assert not routes("a", ip)
        if network:
            until = time.monotonic() + 20
            while time.monotonic() < until:
                old = addr_record("b", ip)
                if old["withdrawn"] and old["lent"] is None and not routes("b", ip):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError("the previous peer did not withdraw the route and release its loan")
        report = {
            "status": "passed",
            "same_tcp_socket": True,
            "separate_state_roots": True,
            "shared_network_namespace": not bool(network),
            "automatic_peer_routes": bool(network),
            "peer_route_withdrawal": bool(network),
            "held_packets": held_packets,
            "outbound": outbound,
            "return": inbound,
            "outbound_bytes": sent,
            "return_bytes": back,
            "elapsed_s": round(time.monotonic() - started, 3),
        }
        (output / "report.json").write_text(json.dumps(report) + "\n")
    finally:
        for owner in owners:
            if owner.poll() is None:
                owner.send_signal(signal.SIGINT)
                try:
                    owner.wait(timeout=8)
                except sp.TimeoutExpired:
                    owner.kill()
                    owner.wait(timeout=8)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=360)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--peer-routes", action="store_true")
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
        with configured_peers(args.peer_routes, args.timeout) as network:
            exercise(binary, kernel, output, engine, args.worker_state, arch, network)
        return 0
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    if report_path.exists():
        parser.error("use an output directory without an existing report")
    try:
        HELPERS["run"]([args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                        str(ROOT / "routed-network-probe.c"), "-o", str(output / "probe")], 60, output / "compile.log")
        trace = output / "files.strace"
        devices = ("/dev/kvm", "/dev/vhost-vsock", "/dev/vhost-net")
        with tempfile.TemporaryDirectory(prefix="flexvm-routed-transfer-", dir="/var/lib") as state:
            mask = Path(state) / "mask"
            mask.touch(mode=0o600)
            setup = """
                ip link set lo up
                ip address add 198.51.100.1/32 dev lo scope global
                for dev in /dev/kvm /dev/vhost-vsock /dev/vhost-net; do
                    if [ -e "$dev" ]; then mount --bind "$1" "$dev"; fi
                done
                shift
                exec "$@"
            """
            HELPERS["run"](["unshare", "--net", "--mount", "--propagation", "private", "sh", "-ec", setup,
                            "sh", str(mask), "strace", "-f", "-e", "trace=file", "-o", str(trace),
                            sys.executable, str(Path(__file__).resolve()), "--bin", str(binary), "--kernel", str(kernel),
                            "--output", str(output), "--worker-state", state,
                            *(["--peer-routes"] if args.peer_routes else [])], args.timeout, output / "worker.log")
        with trace.open(errors="replace") as records:
            if any(f'"{device}"' in line for line in records for device in devices):
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
