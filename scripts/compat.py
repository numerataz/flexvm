#!/usr/bin/env python3
"""Run Linux compatibility probes and verify guest state through VM lifecycle operations.

sudo scripts/compat.py --phases run,suspend,checkpoint --output /tmp/compat-result
sudo scripts/compat.py --vm existing --case capabilities --require storage.fuse

Migration requires a configured peer on this machine: --migration-to HOST:PORT
--to-state STATE [--to-run RUN]. Its artifacts/templates must match the source.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
BASELINE = {"namespace." + name for name in ("user", "mount", "pid", "network", "ipc", "uts", "cgroup")}
BASELINE |= {"cgroup.delegation", "storage.overlay", "storage.capacity", "security.seccomp", "kernel.pidfd", "kernel.memfd"}


class Failure(Exception):
    pass


class Interrupted(Exception):
    pass


def command(argv, timeout=120, stdin=None):
    """Bound and reap the whole host CLI process group, including on interruption."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            errors="replace", start_new_session=True)
    try:
        out, err = proc.communicate(stdin, timeout=timeout)
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        raise
    if proc.returncode:
        raise Failure(f"{shlex.join(map(str, argv))} exited {proc.returncode}\n{err[-4000:]}\n{out[-2000:]}")
    return out


class Host:
    def __init__(self, binary, state=None, run=None):
        self.argv = [binary]
        if state:
            self.argv += ["--state", state]
        if run:
            self.argv += ["--run", run]

    def call(self, *argv, **kw):
        return command(self.argv + list(argv), **kw)


class Suite:
    def __init__(self, args, output):
        self.args, self.output = args, output
        self.source = Host(args.bin, args.state, args.run)
        self.target = Host(args.bin, args.to_state, args.to_run) if args.to_state else None
        self.host = self.source
        self.name = args.vm or "compat-" + uuid.uuid4().hex
        self.image = self.name + "-image"
        self.started = self.pulled = False
        self.checkpoints = []
        self.nonce = uuid.uuid4().hex
        self.probe = "/tmp/flexvm-probe-" + self.nonce
        self.marker = "/tmp/flexvm-state-" + self.nonce
        self.process = None
        self.report = {"schema_version": 1, "vm": self.name, "image": None if args.vm else args.image,
                       "status": "running", "phases": [], "cleanup_errors": []}

    def exec(self, *argv, **kw):
        return self.host.call("exec", self.name, *argv, **kw)

    def start(self, probe):
        if not self.args.vm:
            self.source.call("pull", self.args.image, "--tag", self.image,
                             "--vcpus", str(self.args.vcpus), "--max", str(self.args.memory_mib), timeout=600)
            self.pulled = True
            self.started = True
            self.source.call("run", "-d", "--name", self.name,
                             "--entrypoint", '["sleep","infinity"]', self.image)
        self.source.call("cp", str(probe), f"{self.name}:{self.probe}")
        if "namespaces" in self.args.cases:
            # Mounts are shared with later execs. A live process and its starttime must survive too.
            self.exec("sh", "-ec", 'mkdir "$1"; mount -t tmpfs -o size=1m tmpfs "$1"; printf %s "$2" >"$1/marker"',
                      "sh", self.marker, self.nonce)
            self.host.call("exec", "-d", self.name, "sh", "-ec", 'echo $$ >"$1/pid"; exec sleep infinity', "sh", self.marker)
            for _ in range(50):
                try:
                    self.process = self.exec("sh", "-ec", 'pid=$(cat "$1/pid"); cat "/proc/$pid/stat"', "sh", self.marker).split()
                    break
                except Failure:
                    time.sleep(.1)
            if self.process is None:
                raise Failure("state-check process did not start")

    def verify(self, phase):
        result = {"phase": phase, "status": "running"}
        self.report["phases"].append(result)
        try:
            capabilities = json.loads(self.exec(self.probe, timeout=180))
            if capabilities.get("schema_version") != 1:
                raise Failure("unrecognized capability probe schema")
            result["capabilities"] = capabilities
            required = set(self.args.require)
            if "namespaces" in self.args.cases:
                required |= BASELINE
            probes = {p["name"]: p for p in capabilities["probes"]}
            missing = [f"{name}: {probes.get(name, {}).get('status', 'unknown')} "
                       f"(errno {probes.get(name, {}).get('errno', 'n/a')})"
                       for name in sorted(required) if probes.get(name, {}).get("status") != "supported"]
            if missing:
                raise Failure("required capabilities did not pass: " + "; ".join(missing))
            if "namespaces" in self.args.cases:
                marker = self.exec("cat", self.marker + "/marker")
                if marker != self.nonce:
                    raise Failure("mounted filesystem marker changed")
                state = self.exec("sh", "-ec", 'pid=$(cat "$1/pid"); kill -0 "$pid"; cat "/proc/$pid/stat"', "sh", self.marker).split()
                # The command is a fixed 'sleep', so /proc/PID/stat's comm contains no spaces.
                if (state[0], state[21]) != (self.process[0], self.process[21]):
                    raise Failure("live process identity changed")
            result["status"] = "passed"
        except BaseException as exc:
            result.update(status="failed", error=str(exc))
            raise
        finally:
            self.save()

    def lifecycle(self, phase):
        if phase == "suspend":
            self.host.call("stop", self.name, timeout=300)
            self.host.call("start", self.name, timeout=300)
        elif phase == "checkpoint":
            name = "compat-" + uuid.uuid4().hex
            # A stopped checkpoint requires no host userfaultfd write-protection support.
            self.host.call("checkpoint", "create", self.name, name, "--stop", timeout=300)
            self.checkpoints.append((self.host, name))
            self.host.call("rm", self.name)
            self.host.call("run", "-d", "--checkpoint", name, "--name", self.name, timeout=300)
        elif phase == "migration":
            self.host.call("migrate", self.name, self.args.migration_to, timeout=300)
            self.host = self.target
        self.verify(phase)

    def save(self):
        tmp = self.output / "report.json.tmp"
        tmp.write_text(json.dumps(self.report, indent=2) + "\n")
        tmp.replace(self.output / "report.json")

    def cleanup(self):
        hosts = [self.source] + ([self.target] if self.target else [])
        if self.started:
            # Query first: an absent source VM after migration is expected, other cleanup failures are not.
            for host in hosts:
                try:
                    records = json.loads(host.call("ps", "-a", "--json", timeout=30))
                    if any(r["name"] == self.name for r in records):
                        host.call("rm", "-f", self.name, timeout=60)
                except Exception as exc:
                    self.report["cleanup_errors"].append(str(exc))
        elif self.args.vm:
            try:
                self.exec("rm", self.probe, timeout=30)
            except Exception as exc:
                self.report["cleanup_errors"].append(str(exc))
        for host, name in reversed(self.checkpoints):
            try:
                host.call("checkpoint", "rm", name, timeout=60)
            except Exception as exc:
                self.report["cleanup_errors"].append(str(exc))
        if self.pulled:
            try:
                self.source.call("rmi", self.image, timeout=60)
            except Exception as exc:
                self.report["cleanup_errors"].append(str(exc))
        if self.report["cleanup_errors"]:
            self.report["status"] = "failed"
        self.save()


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bin", default=os.environ.get("FLEXVM_BIN", "flexvm"))
    p.add_argument("--state", default=os.environ.get("FLEXVM_STATE_DIR"))
    p.add_argument("--run")
    p.add_argument("--image", default="ubuntu:24.04")
    p.add_argument("--vm", help="probe an existing VM without changing its lifecycle")
    p.add_argument("--case", dest="cases", action="append", choices=("capabilities", "namespaces"))
    p.add_argument("--require", action="append", default=[], metavar="PROBE", help="fail unless this probe succeeds")
    p.add_argument("--phases", default="run", help="comma-separated run,suspend,checkpoint,migration")
    p.add_argument("--migration-to", metavar="HOST:PORT")
    p.add_argument("--to-state")
    p.add_argument("--to-run")
    p.add_argument("--vcpus", type=int, default=2)
    p.add_argument("--memory-mib", type=int, default=4096)
    p.add_argument("--probe-binary", type=Path, help="prebuilt static guest-probe for the host/guest architecture")
    p.add_argument("--cc", default=os.environ.get("CC", "cc"))
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    args.phases = args.phases.split(",")
    args.cases = args.cases or (["capabilities"] if args.vm else ["capabilities", "namespaces"])
    if not args.phases or args.phases[0] != "run" or len(set(args.phases)) != len(args.phases) or set(args.phases) - {"run", "suspend", "checkpoint", "migration"}:
        p.error("phases must start with run and contain each supported phase at most once")
    if args.vm and (args.phases != ["run"] or "namespaces" in args.cases):
        p.error("--vm supports read-only capability cases in the run phase only")
    if "migration" in args.phases and (not args.migration_to or not args.to_state):
        p.error("migration requires --migration-to and --to-state for a configured local peer")
    if "migration" in args.phases and args.phases[-1] != "migration":
        p.error("migration must be the last phase")
    if args.vcpus < 1 or args.memory_mib < 384:
        p.error("vcpus must be positive and memory-mib at least 384")
    return args


def main(argv=None):
    args = parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    if (args.output / "report.json").exists():
        raise SystemExit("output already contains report.json; choose a new output directory")
    suite = Suite(args, args.output)
    def interrupted(sig, _frame):
        raise Interrupted(f"received signal {sig}")
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        with tempfile.TemporaryDirectory(prefix="flexvm-compat-") as tmp:
            probe = args.probe_binary
            if probe is None:
                probe = Path(tmp) / "guest-probe"
                command([args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                         str(ROOT / "scripts/compat/guest-probe.c"), "-o", str(probe)], timeout=120)
            suite.start(probe)
            suite.verify("run")
            for phase in args.phases[1:]:
                suite.lifecycle(phase)
        suite.report["status"] = "passed"
    except (Interrupted, KeyboardInterrupt) as exc:
        suite.report.update(status="interrupted", error=str(exc))
    except Exception as exc:
        suite.report.update(status="failed", error=str(exc))
        try:
            (args.output / "guest.log").write_text(suite.host.call("logs", "--tail", "100", suite.name, timeout=30))
        except Exception:
            pass
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        suite.cleanup()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(f"{suite.report['status'].upper()}: {args.output / 'report.json'}")
    if suite.report.get("error"):
        print(suite.report["error"], file=sys.stderr)
    return 0 if suite.report["status"] == "passed" else 130 if suite.report["status"] == "interrupted" else 1


if __name__ == "__main__":
    sys.exit(main())
