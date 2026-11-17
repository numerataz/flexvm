#!/usr/bin/env python3
"""Exercise software suspend and fresh-owner restore with host virtualization devices masked."""
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import platform
import runpy
import select
import shutil
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

    def cli(*words, env=None, pending=False):
        result = subprocess.run([*base, *words], capture_output=True, text=True,
                                timeout=max(.1, deadline - time.monotonic()), env=env)
        if pending and result.returncode == 1:
            return None
        if result.returncode:
            raise RuntimeError(f'{words}: exit {result.returncode}: {result.stdout} {result.stderr}')
        return result.stdout

    def live():
        return next((e for e in json.loads(cli('ps', '--json')) if e['name'] == 'state-test'), None)

    def launch(*words, workload_log="workload.log"):
        env = owner_environment()
        with (args.output / workload_log).open('ab') as out, (args.output / f'owner-{len(owners)}.log').open('wb') as err:
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
        until = min(deadline, time.monotonic() + 30)
        while time.monotonic() < until:
            data = cli('exec', 'state-test', '/state-probe', 'status', pending=args.firecracker is not None)
            if data is not None:
                values = [int(v) for v in data.split()]
                if len(values) != 5:
                    raise RuntimeError(f'invalid workload observation: {data}')
                return values
            time.sleep(.1)
        raise TimeoutError('workload did not publish its initial observation')

    def nested_observation():
        values = [int(v) for v in cli('exec', 'state-test', '/state-probe', 'status-full').split()]
        if len(values) != 12:
            raise RuntimeError(f'invalid nested observation: {values}')
        return values

    def nested_mode(mode):
        before = nested_observation()
        cli('exec', 'state-test', '/state-probe', 'mode', mode)
        until = min(deadline, time.monotonic() + 10)
        while time.monotonic() < until:
            seen = nested_observation()
            if seen[10] == (1 if mode == 'spin' else 0) and seen[8] > before[8] and (mode != 'spin' or seen[11] > before[11]):
                return seen
            time.sleep(.1)
        raise RuntimeError(f'inner guest did not enter {mode} mode with forward progress')

    def nested_restored(before, identity):
        initial = nested_observation()
        until = min(deadline, time.monotonic() + 5)
        while time.monotonic() < until:
            time.sleep(.15)
            seen = nested_observation()
            if initial[:8] != identity[:8] or seen[:8] != identity[:8] or seen[10] != before[10]:
                raise RuntimeError(f'inner process/RAM/mode continuity lost: {before} -> {seen}')
            if seen[10] == 0 and (initial[11] != before[11] or seen[11] != before[11]):
                raise RuntimeError('timer workload unexpectedly executed the CPU spin loop')
            if seen[8] >= initial[8] + 2 and seen[8] > before[8] and seen[9] > initial[9] and seen[9] > before[9]:
                if seen[10] == 0 or (seen[11] > initial[11] and seen[11] > before[11]):
                    return seen
        raise RuntimeError('inner CPU/timer did not make fresh post-restore progress')

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
        try:
            pidfd = os.pidfd_open(ident['pid'])
        except ProcessLookupError:
            return
        try:
            try:
                fields = Path(f'/proc/{ident["pid"]}/stat').read_text().rsplit(')', 1)[1].split()
            except FileNotFoundError:
                return
            if int(fields[19]) != ident['start']:
                return
            # A zombie leader can precede its last exiting worker thread.
            waiter = select.poll()
            waiter.register(pidfd, select.POLLIN)
            if not waiter.poll(max(1, int(min(5, deadline - time.monotonic()) * 1000))):
                raise RuntimeError('software engine thread group survived its owner')
        finally:
            os.close(pidfd)

    boot = ('software', '--name', 'state-test', '--control', 'serial', '--kernel', str(args.kernel),
            '--mem', '512', '--vcpus', '2' if args.firecracker else '1', str(args.output / 'image.tar'))

    def transfer_retirement():
        target = [str(args.bin), '--state', str(args.state / 'target'), 'software-transfer']

        def destination(*words):
            return json.loads(subprocess.check_output([*target, *words], timeout=max(.1, deadline - time.monotonic())))

        cli('rm', '-f', 'state-test', pending=True)
        owner, entry = launch(*boot, workload_log='transfer-workload.log')
        observation()
        cli('stop', 'state-test')
        if owner.wait(timeout=10) != 0:
            raise RuntimeError('transfer source owner did not retire')
        engine_gone(entry['backend']['process'])

        secret = args.state / 'signing-key.der'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-outform', 'DER', '-out', secret], check=True, timeout=10)
        secret.chmod(0o600)
        public_der = subprocess.check_output(['openssl', 'pkey', '-inform', 'DER', '-in', secret, '-pubout', '-outform', 'DER'], timeout=10)
        public_key = base64.b64encode(public_der[-32:]).decode()
        offer = args.state / 'offer.json'
        offer.write_text(cli('software-transfer', 'offer', 'state-test', destination('id')['host_id']))
        if destination('prepare', offer, '--source-key', public_key)['status'] != 'pending':
            raise RuntimeError('transfer destination did not prepare')
        receipt = args.state / 'receipt.json'
        retire = ('software-transfer', 'retire', 'state-test', offer, '--signing-key', secret)
        receipt.write_text(cli(*retire))
        if json.loads(cli(*retire)) != json.loads(receipt.read_text()) or destination('commit', receipt)['status'] != 'committed':
            raise RuntimeError('transfer receipt retry or destination commit failed')
        refused = subprocess.run([*base, 'start', 'state-test'], capture_output=True, text=True, timeout=30)
        if refused.returncode == 0 or 'source cannot restart' not in refused.stderr or live() is not None:
            raise RuntimeError(f'transfer source restarted or failed for another reason: {refused}')
        cli('rm', '-f', 'state-test')

    evidence = {'cycles': []}
    try:
        owner, entry = launch(*boot)
        first = observation()
        identity = entry['gen']
        nested_identity = nested_observation() if args.firecracker else None
        for cycle in range(2):
            nested_before = None
            if args.firecracker:
                mode = 'spin' if cycle == 0 else 'timer'
                nested_before = nested_mode(mode)
                cli('pause', 'state-test')
                if live()['state'] != 'paused':
                    raise RuntimeError('nested pause did not confirm outer CPU state')
                cli('unpause', 'state-test')
                advancing_observation()
            before = observation()
            if args.firecracker:
                nested_before = nested_observation()
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
                if args.firecracker:
                    nested_before = nested_observation()
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
            cycle_evidence = {'before': before, 'after': after, 'entry': entry}
            if args.firecracker:
                nested_after = nested_restored(nested_before, nested_identity)
                cycle_evidence.update(nested_mode=mode, nested_before=nested_before, nested_after=nested_after)
            evidence['cycles'].append(cycle_evidence)
        # Exercise the normal detached start notification and owner handoff too.
        before = observation()
        nested_before = nested_observation() if args.firecracker else None
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
        if args.firecracker:
            evidence['detached_start'].update(nested_before=nested_before, nested_after=nested_restored(nested_before, nested_identity))
        # Kill the owner after exchange, before parent fsync/RETIRED. The new
        # complete checkpoint must survive collection and recover on this host.
        checkpoint = args.state / 'state' / 'suspended' / 'state-test'
        old_snapshot = json.loads((checkpoint / 'manifest.json').read_text())['snapshot_id']
        before = observation()
        nested_before = nested_observation() if args.firecracker else None
        marker = args.output / 'kill-parent-sync'
        owner_pidfd = os.pidfd_open(entry['pid'])
        try:
            marker.touch()
            crashed = subprocess.run([*base, 'stop', 'state-test'], capture_output=True, text=True, timeout=60)
            if crashed.returncode == 0 or marker.exists():
                raise RuntimeError('replacement owner-death fault did not execute')
            waiter = select.poll()
            waiter.register(owner_pidfd, select.POLLIN)
            if not waiter.poll(5000):
                raise RuntimeError('publication owner thread group did not exit')
        finally:
            os.close(owner_pidfd)
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
        if args.firecracker:
            evidence['publication_owner_death'].update(nested_before=nested_before, nested_after=nested_restored(nested_before, nested_identity))
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
        if args.firecracker:
            if lines.count('NESTED_INNER_BOOT') != 1 or lines.count('NESTED_INNER_READY') != 1:
                raise RuntimeError('nested Firecracker guest booted repeatedly or never completed startup')
            evidence['nested_firecracker'] = {'boots': 1, 'identity': nested_identity[:8], 'cpu_and_timer_restore': 'passed'}
        else:
            transfer_retirement()
            evidence['source_transfer_retirement'] = 'passed'
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
    parser.add_argument('--firecracker', type=Path, help='run a live inner Linux VM through the normal software owner')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--state', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.bin, args.kernel, args.output = (p.resolve() for p in (args.bin, args.kernel, args.output))
    if args.firecracker:
        args.firecracker = args.firecracker.resolve(strict=True)
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
        engine = shutil.which('qemu-system-' + platform.machine())
        if engine is None:
            raise FileNotFoundError('native QEMU is required for lifecycle acceptance')
        report['qemu_sha256'] = HELPERS['digest'](Path(engine).resolve())
        report['qemu_version'] = subprocess.check_output([engine, '--version'], text=True, timeout=10).splitlines()[0]
        probe = args.output / 'state-probe'
        source = ROOT / ('nested-state.c' if args.firecracker else 'state-probe.c')
        HELPERS['run']([args.cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-pthread', str(source), '-o', str(probe)],
                       60, args.output / 'compile.log')
        HELPERS['run']([args.cc, '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                        str(ROOT / 'fail-parent-sync.c'), '-ldl', '-o', str(args.output / 'fail-parent-sync.so')],
                       60, args.output / 'compile-fault.log')
        files = {'state-probe': (probe.read_bytes(), 0o755), 'etc/passwd': (b'root:x:0:0:root:/root:/bin/sh\n', 0o644),
                 'etc/group': (b'root:x:0:\n', 0o644)}
        if args.firecracker:
            config = {'boot-source': {'kernel_image_path': '/inner-kernel', 'initrd_path': '/inner-initramfs.cpio',
                                      'boot_args': 'console=ttyS0 quiet panic=1 rdinit=/init' + (' reboot=k' if platform.machine() == 'x86_64' else '')},
                      'machine-config': {'vcpu_count': 1, 'mem_size_mib': 128}, 'drives': [], 'network-interfaces': []}
            files.update({'firecracker': (args.firecracker.read_bytes(), 0o755), 'inner-kernel': (args.kernel.read_bytes(), 0o600),
                          'inner-initramfs.cpio': (HELPERS['initramfs'](probe.read_bytes()), 0o600),
                          'firecracker.json': (json.dumps(config).encode(), 0o600)})
            report.update(scope='nested Firecracker through named software lifecycle',
                          firecracker_sha256=HELPERS['digest'](args.firecracker), inner_kernel_sha256=HELPERS['digest'](args.kernel))
        IMAGE(args.output / 'image.tar', 'amd64' if platform.machine() == 'x86_64' else 'arm64', files, ['/state-probe'])
        with tempfile.TemporaryDirectory(prefix='flexvm-software-lifecycle-', dir='/var/lib') as state:
            mask = args.output / 'unusable-device'
            mask.touch(mode=0o600)
            trace = args.output / 'files.strace'
            command = ['unshare', '--mount', '--propagation', 'private', 'sh', '-ec',
                       'for dev in /dev/kvm /dev/vhost-vsock; do if [ -e "$dev" ]; then mount --bind "$1" "$dev"; fi; done; shift; exec "$@"',
                       'sh', str(mask), 'strace', '-f', '-e', 'trace=file', '-o', str(trace), sys.executable, str(Path(__file__).resolve()),
                       '--worker', '--bin', str(args.bin), '--kernel', str(args.kernel), '--output', str(args.output), '--state', state,
                       '--timeout', str(args.timeout)]
            if args.firecracker:
                command += ['--firecracker', str(args.firecracker)]
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
