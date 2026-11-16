#!/usr/bin/env python3
"""Exercise software suspend and fresh-owner restore with host virtualization devices masked."""
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
    owners = []

    def owner_environment():
        env = os.environ.copy()
        env['LD_PRELOAD'] = str(args.output / 'fail-parent-sync.so')
        env['FLEXVM_TEST_FAIL_PARENT_SYNC'] = str(args.output / 'fail-parent-sync')
        env['FLEXVM_TEST_KILL_PARENT_SYNC'] = str(args.output / 'kill-parent-sync')
        return env

    def cli(*words, env=None):
        result = subprocess.run([*base, *words], capture_output=True, text=True,
                                timeout=max(.1, deadline - time.monotonic()), env=env)
        if result.returncode:
            raise RuntimeError(f'{words}: exit {result.returncode}: {result.stdout} {result.stderr}')
        return result.stdout

    def live():
        return next((e for e in json.loads(cli('ps', '--json')) if e['name'] == 'state-test'), None)

    def launch(*words):
        env = owner_environment()
        with (args.output / 'workload.log').open('ab') as out, (args.output / f'owner-{len(owners)}.log').open('wb') as err:
            proc = subprocess.Popen([*base, *words], stdout=out, stderr=err, env=env)
        owners.append(proc)
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f'owner exited {proc.returncode}; see owner-{len(owners)-1}.log')
            entry = live()
            if entry:
                return proc, entry
            time.sleep(.05)
        raise TimeoutError('owner did not publish')

    def observation():
        return [int(v) for v in cli('exec', 'state-test', '/state-probe', 'status').split()]

    def advancing_observation():
        initial = observation()
        until = min(deadline, time.monotonic() + 3)
        while time.monotonic() < until:
            time.sleep(.15)
            latest = observation()
            if latest[:3] != initial[:3] or latest[4] < initial[4]:
                raise RuntimeError('restored workload identity or monotonic clock changed')
            if latest[3] > initial[3] and latest[4] > initial[4]:
                return latest
        raise RuntimeError('restored workload timers did not make forward progress')

    def engine_gone(ident):
        until = min(deadline, time.monotonic() + 5)
        while time.monotonic() < until:
            try:
                fields = Path(f'/proc/{ident["pid"]}/stat').read_text().rsplit(')', 1)[1].split()
            except FileNotFoundError:
                return
            if fields[0] == 'Z' or int(fields[19]) != ident['start']:
                return
            time.sleep(.02)
        raise RuntimeError('retired engine survived')

    evidence = {'cycles': []}
    try:
        owner, entry = launch('software', '--name', 'state-test', '--control', 'serial', '--kernel', str(args.kernel),
                              '--mem', '512', str(args.output / 'image.tar'))
        first = observation()
        identity = entry['gen']
        for cycle in range(2):
            before = observation()
            if cycle == 1:
                # Fail the parent directory fsync after the replacement rename.
                # Roll back explicitly, then capture again from the same engine.
                marker = args.output / 'fail-parent-sync'
                marker.touch()
                refused = subprocess.run([*base, 'stop', 'state-test'], capture_output=True, text=True, timeout=60)
                if refused.returncode == 0 or marker.exists() or live()['state'] != 'paused':
                    raise RuntimeError(f'publication fault was not fenced: {refused}')
                retried = subprocess.run([*base, 'stop', 'state-test'], capture_output=True, text=True, timeout=10)
                if retried.returncode == 0 or 'unresolved' not in retried.stderr:
                    raise RuntimeError('retried stop overwrote the pending capture identity')
                cli('unpause', 'state-test')
                # The rollback keeps the consumed inputs at an exchange name.
                # A sweep must preserve their links while QEMU still uses them.
                hidden = list((args.state / 'state' / 'suspended').glob('.software-stage-v2-*'))
                if not hidden:
                    raise RuntimeError('replacement rollback did not retain the consumed inputs')
                pinned = {str(path): (path.stat().st_ino, (path / 'kernel').stat().st_ino) for path in hidden}
                cli('debug', 'gc')
                if any(not Path(path).exists() or (Path(path).stat().st_ino, (Path(path) / 'kernel').stat().st_ino) != inode
                       for path, inode in pinned.items()):
                    raise RuntimeError('garbage collection removed live exchanged inputs')
                evidence['live_input_gc'] = 'passed'
                rolled_back = observation()
                if rolled_back[:3] != first[:3] or rolled_back[3] < before[3]:
                    raise RuntimeError('publication rollback lost source identity')
                evidence['publication_rollback'] = {'error': refused.stderr, 'source': rolled_back}
                cli('pause', 'state-test')
            cli('stop', 'state-test')
            if owner.wait(timeout=10) != 0:
                raise RuntimeError('suspend owner failed')
            engine_gone(entry['backend']['process'])
            if list((args.state / 'state' / 'suspended').glob('.software-stage-*')):
                raise RuntimeError('retired owner left a replaced checkpoint bundle')
            stopped = next(e for e in json.loads(cli('ps', '-a', '--json')) if e['name'] == 'state-test')
            if stopped['state'] != 'suspended' or stopped['backend']['kind'] != 'qemu-tcg':
                raise RuntimeError(f'wrong suspended identity: {stopped}')
            if cycle == 0:
                # Corrupt a pinned input: restore must refuse before granting CPU
                # authority, and the unconsumed checkpoint must remain usable.
                kernel = args.state / 'state' / 'suspended' / 'state-test' / 'kernel'
                original = kernel.read_bytes()
                kernel.chmod(0o600)
                kernel.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                kernel.chmod(0o400)
                try:
                    refused = subprocess.run([*base, 'start', '--attach', 'state-test'],
                                             capture_output=True, text=True, timeout=30)
                    if refused.returncode == 0 or live() is not None:
                        raise RuntimeError('corrupt kernel was accepted')
                    evidence['corrupt_kernel_refused'] = refused.stderr
                finally:
                    kernel.chmod(0o600)
                    kernel.write_bytes(original)
                    kernel.chmod(0o400)
            owner, entry = launch('start', '--attach', 'state-test')
            after = advancing_observation()
            if after[:3] != first[:3] or after[3] < before[3] or after[4] < before[4] or entry['gen'] != identity:
                raise RuntimeError(f'workload continuity lost: {before} -> {after}; {entry}')
            evidence['cycles'].append({'before': before, 'after': after, 'entry': entry})
        # Exercise the normal detached start notification and owner handoff too.
        before = observation()
        cli('stop', 'state-test')
        if owner.wait(timeout=10) != 0:
            raise RuntimeError('last attached owner failed to suspend')
        engine_gone(entry['backend']['process'])
        cli('start', 'state-test', env=owner_environment())
        entry = live()
        after = advancing_observation()
        if not entry or after[:3] != first[:3] or after[3] < before[3] or entry['gen'] != identity:
            raise RuntimeError('detached start lost workload identity')
        evidence['detached_start'] = {'before': before, 'after': after, 'entry': entry}
        # Kill the owner after exchange, before parent fsync/RETIRED. The new
        # complete checkpoint must survive collection and recover on this host.
        checkpoint = args.state / 'state' / 'suspended' / 'state-test'
        old_snapshot = json.loads((checkpoint / 'manifest.json').read_text())['snapshot_id']
        before = observation()
        marker = args.output / 'kill-parent-sync'
        marker.touch()
        crashed = subprocess.run([*base, 'stop', 'state-test'], capture_output=True, text=True, timeout=60)
        if crashed.returncode == 0 or marker.exists():
            raise RuntimeError('replacement owner-death fault did not execute')
        engine_gone(entry['backend']['process'])
        published = json.loads((checkpoint / 'manifest.json').read_text())
        if published['snapshot_id'] == old_snapshot or (checkpoint / 'RETIRED').exists() or (checkpoint / 'STARTED').exists():
            raise RuntimeError('replacement crash did not leave the expected unretired publication')
        cli('debug', 'gc')
        if list(checkpoint.parent.glob('.software-stage-v2-*')):
            raise RuntimeError('dead replacement owner retained hidden input bundles')
        if json.loads((checkpoint / 'manifest.json').read_text()) != published:
            raise RuntimeError('collection changed the last complete checkpoint')
        cli('start', 'state-test', env=owner_environment())
        entry = live()
        after = advancing_observation()
        if not entry or after[:3] != first[:3] or after[3] < before[3] or entry['gen'] != identity:
            raise RuntimeError('commit-before-retirement recovery lost workload continuity')
        evidence['publication_owner_death'] = {'snapshot_id': published['snapshot_id'], 'before': before, 'after': after,
                                               'runtime_and_staging_cleanup': 'passed'}
        cli('kill', 'state-test')
        if cli('wait', 'state-test').strip() != '130':
            raise RuntimeError('detached owner lost kill status')
        engine_gone(entry['backend']['process'])
        ended = next((e for e in json.loads(cli('ps', '-a', '--json')) if e['name'] == 'state-test'), None)
        if ended and ended['state'] == 'quarantined':
            raise RuntimeError('explicit kill retained a replay-quarantined checkpoint')
        lines = (args.output / 'workload.log').read_text().splitlines()
        ticks = [int(line.split()[1]) for line in lines if line.startswith('STATE_TICK ')]
        if lines.count('STATE_WORKLOAD_BOOT') != 1 or not ticks or ticks != list(range(ticks[-1] + 1)):
            raise RuntimeError(f'foreground output duplicated or skipped: {lines}')
        evidence.update(status='passed', boots=1, delivered_ticks=len(ticks))
        (args.output / 'owner.json').write_text(json.dumps(evidence, indent=2) + '\n')
    finally:
        try:
            subprocess.run([*base, 'kill', 'state-test'], capture_output=True, timeout=5)
        except subprocess.TimeoutExpired:
            pass
        for owner in owners:
            if owner.poll() is None:
                owner.send_signal(signal.SIGINT)
                try:
                    owner.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    owner.kill()
                    owner.wait(timeout=5)


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
    report = {'schema_version': 1, 'status': 'running', 'scope': 'software lifecycle continuity',
              'binary_sha256': HELPERS['digest'](args.bin), 'kernel_sha256': HELPERS['digest'](args.kernel)}
    started = time.monotonic()
    def interrupted(number, _frame):
        raise HELPERS['Interrupted'](number)
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        probe = args.output / 'state-probe'
        HELPERS['run']([args.cc, '-O2', '-Wall', '-Wextra', '-Werror', '-static', str(ROOT / 'state-probe.c'), '-o', str(probe)],
                       60, args.output / 'compile.log')
        HELPERS['run']([args.cc, '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                        str(ROOT / 'fail-parent-sync.c'), '-ldl', '-o', str(args.output / 'fail-parent-sync.so')],
                       60, args.output / 'compile-fault.log')
        IMAGE(args.output / 'image.tar', 'amd64' if platform.machine() == 'x86_64' else 'arm64', {
            'state-probe': (probe.read_bytes(), 0o755), 'etc/passwd': (b'root:x:0:0:root:/root:/bin/sh\n', 0o644),
            'etc/group': (b'root:x:0:\n', 0o644)}, ['/state-probe'])
        with tempfile.TemporaryDirectory(prefix='flexvm-software-lifecycle-', dir='/var/lib') as state:
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
