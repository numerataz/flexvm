#!/usr/bin/env python3
"""Exercise named software ownership with host virtualization devices masked."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import runpy
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / 'software-boot.py'))
IMAGE = runpy.run_path(str(ROOT / 'software-kvm.py'))['image']


def exercise(args):
    base = [str(args.bin), '--state', str(args.state / 'state'), '--run', str(args.state / 'run')]
    deadline = time.monotonic() + args.timeout

    def cli(*words, status=0):
        result = subprocess.run([*base, *words], capture_output=True, text=True,
                                timeout=max(.1, deadline - time.monotonic()))
        if status is not None and result.returncode != status:
            raise RuntimeError(f'{words}: exit {result.returncode}: {result.stdout} {result.stderr}')
        return result

    def live(name):
        return next((entry for entry in json.loads(cli('ps', '--json').stdout) if entry['name'] == name), None)

    def start(name, ignore_interrupt=False):
        log = (args.output / (name + '.log')).open('wb')
        proc = subprocess.Popen([*base, 'software', '--name', name, '--control', 'serial', '--kernel', str(args.kernel),
                                 '--mem', '512', str(args.output / 'image.tar')], stdout=log, stderr=subprocess.STDOUT,
                                preexec_fn=(lambda: signal.signal(signal.SIGINT, signal.SIG_IGN)) if ignore_interrupt else None)
        log.close()
        try:
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError(f'owner exited during startup: {proc.returncode}; see {name}.log')
                entry = live(name)
                if entry:
                    return proc, entry
                time.sleep(.05)
            raise TimeoutError('named owner did not become ready')
        except BaseException:
            stop(proc)
            raise

    def stop(proc):
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    def engine_gone(ident):
        path = Path(f'/proc/{ident["pid"]}/stat')
        until = min(deadline, time.monotonic() + 5)
        while time.monotonic() < until:
            try:
                fields = path.read_text().rsplit(')', 1)[1].split()
            except FileNotFoundError:
                return
            if fields[0] == 'Z' or int(fields[19]) != ident['start']:
                return
            time.sleep(.02)
        raise RuntimeError('software engine survived its owner')

    owner, entry = start('owner-test')
    evidence = {'entry': entry}
    try:
        if entry['backend']['kind'] != 'qemu-tcg' or entry.get('firecracker') is not None:
            raise RuntimeError('owner did not publish an honest software backend identity')
        if entry['max_mib'] != 512 or entry['backend']['ram_mib'] != 512 or entry.get('template_id'):
            raise RuntimeError('wrong RAM reservation or fake template identity')
        inspect = json.loads(cli('inspect', 'owner-test').stdout)
        if isinstance(inspect, list):
            inspect = inspect[0]
        if inspect['config']['backend']['kind'] != 'qemu-tcg' or inspect['config']['template'] is not None:
            raise RuntimeError('inspect misidentified the software VM')
        executed = cli('exec', '--user', '1001:1001', '--workdir', '/tmp', '--env', 'OWNER_TEST=value',
                       'owner-test', '/owner-probe', 'exec', 'literal $HOME *', status=17)
        if executed.stdout != 'uid=1001 gid=1001 cwd=/tmp env=value arg=literal $HOME *\n' or 'OWNER_EXEC_STDERR' not in executed.stderr:
            raise RuntimeError(f'named exec changed argv/credentials/env/output: {executed}')
        for _ in range(2):
            cli('pause', 'owner-test')
            if live('owner-test')['state'] != 'paused':
                raise RuntimeError('pause did not publish verified engine state')
            cli('unpause', 'owner-test')
            if live('owner-test')['state'] != 'running':
                raise RuntimeError('unpause did not publish verified engine state')
        refused = cli('stop', 'owner-test', status=None)
        if refused.returncode == 0 or 'not implemented' not in refused.stderr or owner.poll() is not None:
            raise RuntimeError('unsupported suspend destroyed the software VM or falsely succeeded')
        owner.send_signal(signal.SIGTERM)
        time.sleep(.1)
        if owner.poll() is not None:
            raise RuntimeError('legacy suspend signal destroyed a named software VM')
        # This command ends the main workload, which tears down the VM and may
        # close the exec connection before its own reply. The main status below
        # proves that the finish request actually ran.
        finished = cli('exec', 'owner-test', '/owner-probe', 'finish', status=None)
        lost_after_exit = finished.returncode == 125 and not finished.stdout and finished.stderr.strip() == 'flexvm: no vm named "owner-test"'
        if finished.returncode != 0 and not lost_after_exit:
            raise RuntimeError(f'finish command failed unexpectedly: {finished}')
        if owner.wait(timeout=10) != 23 or cli('wait', 'owner-test').stdout.strip() != '23':
            raise RuntimeError('owner exit status was lost')
        engine_gone(entry['backend']['process'])
        if live('owner-test') is not None:
            raise RuntimeError('ended owner stayed live in registry')
        killed, killed_entry = start('owner-kill', ignore_interrupt=True)
        try:
            cli('kill', 'owner-kill')
            if killed.wait(timeout=10) != -signal.SIGINT or cli('wait', 'owner-kill').stdout.strip() != '130':
                raise RuntimeError('management kill or its recorded signal status was lost')
            engine_gone(killed_entry['backend']['process'])
        finally:
            stop(killed)
        # A hard owner death must also fence and terminate its actual engine.
        crashed, crash_entry = start('owner-crash')
        try:
            crashed.kill()
            crashed.wait(timeout=5)
            engine_gone(crash_entry['backend']['process'])
            if live('owner-crash') is not None:
                raise RuntimeError('dead owner remained live in registry')
            evidence['crash_engine'] = crash_entry['backend']['process']
        finally:
            stop(crashed)
        # Flock ownership, rather than an old pathname, determines live reservations.
        for hold in (args.state / 'run').rglob('holds/*-*'):
            with hold.open('rb') as stream:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        evidence.update(status='passed', exec_status=17, owner_status=23, pause_cycles=2, owner_death_cleanup='passed')
        (args.output / 'owner.json').write_text(json.dumps(evidence, indent=2) + '\n')
    finally:
        stop(owner)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--state', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.bin, args.kernel, args.output = (p.resolve() for p in (args.bin, args.kernel, args.output))
    if args.worker:
        exercise(args)
        return 0
    if os.geteuid() != 0:
        parser.error('run as root for image preparation and private device masking')
    if not 1 <= args.timeout <= 3600:
        parser.error('--timeout must be 1..3600 seconds')
    args.output.mkdir(parents=True, exist_ok=True)
    report_path = args.output / 'report.json'
    if report_path.exists():
        parser.error('use an output directory without an existing report')
    report = {'schema_version': 1, 'status': 'running', 'scope': 'named software VM ownership',
              'binary_sha256': HELPERS['digest'](args.bin), 'kernel_sha256': HELPERS['digest'](args.kernel)}
    started = time.monotonic()
    def interrupted(number, _frame):
        raise HELPERS['Interrupted'](number)
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        probe = args.output / 'owner-probe'
        HELPERS['run']([args.cc, '-O2', '-Wall', '-Wextra', '-Werror', '-static', str(ROOT / 'owner-probe.c'), '-o', str(probe)],
                       60, args.output / 'compile.log')
        IMAGE(args.output / 'image.tar', 'amd64' if platform.machine() == 'x86_64' else 'arm64', {
            'owner-probe': (probe.read_bytes(), 0o755), 'etc/passwd': (b'root:x:0:0:root:/root:/bin/sh\n', 0o644),
            'etc/group': (b'root:x:0:\n', 0o644)}, ['/owner-probe'])
        with tempfile.TemporaryDirectory(prefix='flexvm-software-owner-', dir='/var/lib') as state:
            mask = args.output / 'unusable-device'
            mask.touch(mode=0o600)
            trace = args.output / 'files.strace'
            command = ['unshare', '--mount', '--propagation', 'private', 'sh', '-ec',
                       'for dev in /dev/kvm /dev/vhost-vsock; do if [ -e "$dev" ]; then mount --bind "$1" "$dev"; fi; done; shift; exec "$@"',
                       'sh', str(mask), 'strace', '-f', '-e', 'trace=file', '-o', str(trace), sys.executable, str(Path(__file__).resolve()),
                       '--worker', '--bin', str(args.bin), '--kernel', str(args.kernel), '--output', str(args.output), '--state', state,
                       '--timeout', str(args.timeout)]
            HELPERS['run'](command, args.timeout, args.output / 'worker.log')
            if any(f'"{dev}"' in trace.read_text(errors='replace') for dev in ('/dev/kvm', '/dev/vhost-vsock')):
                raise RuntimeError('host virtualization device access; see files.strace')
        report.update(status='passed', owner=json.loads((args.output / 'owner.json').read_text()), kvm_access=False, vhost_vsock_access=False)
    except HELPERS['Interrupted'] as exc:
        report.update(status='interrupted', signal=exc.number, error=str(exc))
    except Exception as exc:
        report.update(status='failed', error=str(exc))
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    report['elapsed_s'] = round(time.monotonic() - started, 3)
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['status'].upper()}: {report_path}")
    return 128 + report['signal'] if report['status'] == 'interrupted' else (0 if report['status'] == 'passed' else 1)


if __name__ == '__main__':
    raise SystemExit(main())
