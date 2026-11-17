#!/usr/bin/env python3
"""Run ordinary guest workloads through software VM lifecycle without host virtualization."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import platform
import re
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / 'software-boot.py'))
ENGINE_GONE = runpy.run_path(str(ROOT / 'software-modules.py'))['engine_gone']
BASELINE = runpy.run_path(str(ROOT.parent / 'compat.py'))['BASELINE']
IMAGE = 'public.ecr.aws/docker/library/ubuntu@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8'
NAME = 'workload-test'


def exercise(args):
    base = [str(args.bin), '--state', str(args.state / 'state'), '--run', str(args.state / 'run')]
    deadline = time.monotonic() + args.timeout
    environment = os.environ.copy()
    auth = args.output / 'anonymous-auth'
    auth.mkdir(mode=0o700)
    environment['DOCKER_CONFIG'] = str(auth)
    workload = args.workload.read_text()
    inode_probe = (ROOT / "root-inodes.sh").read_text()
    nonce = uuid.uuid4().hex
    owner = None
    evidence = {'status': 'running', 'phases': []}

    def cli(*words, input=None, check=True, result=False):
        binary = isinstance(input, bytes)
        completed = subprocess.run([*base, *words], input=input, capture_output=True, text=not binary,
                                timeout=max(.1, deadline - time.monotonic()), env=environment)
        out = completed.stdout.decode(errors='replace') if binary else completed.stdout
        err = completed.stderr.decode(errors='replace') if binary else completed.stderr
        if check and completed.returncode:
            raise RuntimeError(f'{words[:4]}: exit {completed.returncode}: {out[-2000:]} {err[-4000:]}')
        return completed if result else out

    def entry():
        return next((item for item in json.loads(cli('ps', '--json')) if item['name'] == NAME), None)

    def ready():
        while time.monotonic() < deadline:
            if owner.poll() is not None:
                raise RuntimeError(f'owner exited {owner.returncode}; see owner/restore log')
            value = entry()
            if value and value['state'] == 'running':
                return value
            time.sleep(.1)
        raise TimeoutError('software owner did not publish')

    def observation():
        values = [int(value) for value in cli('exec', NAME, '/state-probe', 'status').split()]
        if len(values) != 5:
            raise RuntimeError(f'invalid userspace observation: {values}')
        return values

    def advancing(before):
        initial = observation()
        until = min(deadline, time.monotonic() + 15)
        while time.monotonic() < until:
            seen = observation()
            if initial[:3] != before[:3] or seen[:3] != before[:3]:
                raise RuntimeError('foreground PID/start time/random RAM changed')
            if seen[3] > initial[3] and seen[4] > initial[4] and seen[3] > before[3]:
                return seen
            time.sleep(.2)
        raise RuntimeError('foreground canary did not make fresh progress')

    def step(action, phase):
        completed = cli('exec', '-i', NAME, '/bin/sh', '-s', '--', action, nonce, phase,
                        input=workload, check=False, result=True)
        (args.output / f'{action}-{phase}.log').write_text(completed.stdout)
        (args.output / f'{action}-{phase}.stderr.log').write_text(completed.stderr)
        if completed.returncode:
            raise RuntimeError(f'workload {action}-{phase} exited {completed.returncode}; see its stdout/stderr logs')
        return completed.stdout

    def verify(phase, before):
        capabilities = json.loads(cli('exec', NAME, '/guest-probe'))
        probes = {item['name']: item for item in capabilities['probes']}
        required = BASELINE | set(args.require)
        missing = [name for name in sorted(required) if probes.get(name, {}).get('status') != 'supported']
        if capabilities.get('schema_version') != 1 or missing:
            raise RuntimeError(f'guest capabilities failed: {missing}; {capabilities}')
        inode_identity = cli('exec', '-i', NAME, '/bin/sh', '-s', '--', 'verify', nonce, input=inode_probe)
        output = step('verify', phase)
        seen = advancing(before)
        evidence['phases'].append({'phase': phase, 'status': 'passed', 'capabilities': capabilities,
                                   'workload': output, 'process': seen, 'inode_identity': inode_identity})
        (args.output / 'owner.json').write_text(json.dumps(evidence, indent=2) + '\n')
        return seen

    try:
        gate = 'while [ ! -x /state-probe ]; do sleep .05; done; exec /state-probe'
        with (args.output / 'guest.log').open('w') as out, (args.output / 'owner.log').open('w') as err:
            owner = subprocess.Popen([*base, 'software', '--name', NAME, '--control', 'serial', '--kernel', str(args.kernel),
                                      '--mem', str(args.mem), '--vcpus', str(args.vcpus), '--timeout', '120', '--boot', args.boot,
                                      *(['--entrypoint', '[]', args.image, '/bin/sh', '-ec', gate] if args.boot == 'app' else [args.image])], stdout=out, stderr=err, env=environment)
        ready()
        # Software management supports streaming exec. Transfer opaque guest
        # binaries through stdin instead of assuming the KVM-only cp operation.
        for name in ('guest-probe', 'state-probe'):
            cli('exec', '-i', NAME, '/bin/sh', '-ec', f'cat >/{name}.tmp; chmod 755 /{name}.tmp; mv /{name}.tmp /{name}',
                input=(args.output / name).read_bytes())
        if args.boot == 'systemd':
            cli('exec', NAME, 'systemd-run', '--unit=flexvm-state-probe', '--collect', '/state-probe')
        elif args.boot == 'openrc':
            cli('exec', NAME, '/bin/sh', '-ec', '''cat >/etc/init.d/flexvm-state-probe <<'SERVICE'
#!/sbin/openrc-run
supervisor=supervise-daemon
command=/state-probe
output_log=/var/log/flexvm-state-probe.log
error_log=/var/log/flexvm-state-probe.log
rc_cgroup_settings="memory.max 67108864
pids.max 16"
SERVICE
chmod 755 /etc/init.d/flexvm-state-probe
rc-service flexvm-state-probe start''')
        if args.boot != 'app':
            cli('exec', NAME, '/bin/sh', '-ec', 'while [ ! -s /tmp/state-observation ]; do sleep .05; done')
        else:
            while 'STATE_WORKLOAD_BOOT' not in (args.output / 'guest.log').read_text(errors='replace'):
                if owner.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('foreground canary did not start')
                time.sleep(.1)
        before = observation()
        evidence['initial_process'] = before
        (args.output / 'owner.json').write_text(json.dumps(evidence, indent=2) + '\n')
        evidence['root_filesystem'] = cli('exec', '-i', NAME, '/bin/sh', '-s', '--', 'prepare', nonce, input=inode_probe)
        evidence['prepare'] = step('prepare', 'run')
        before = verify('run', before)
        cli('pause', NAME)
        if entry()['state'] != 'paused':
            raise RuntimeError('pause did not fence the software VM')
        cli('unpause', NAME)
        before = verify('pause', before)
        source = entry()['backend']['process']
        cli('stop', NAME)
        owner.wait(timeout=10)
        ENGINE_GONE(source, deadline)
        with (args.output / 'guest.log').open('a') as out, (args.output / 'restore.log').open('w') as err:
            owner = subprocess.Popen([*base, 'start', '--attach', NAME], stdout=out, stderr=err, env=environment)
        target = ready()['backend']['process']
        if source == target:
            raise RuntimeError('restoration reused the source emulator')
        verify('stop-start', before)
        if args.boot == 'systemd':
            journal = cli('exec', NAME, 'journalctl', '--unit=flexvm-state-probe', '--output=cat', '--no-pager')
            (args.output / 'guest.log').write_text(journal)
        elif args.boot == 'openrc':
            (args.output / 'guest.log').write_text(cli('exec', NAME, 'cat', '/var/log/flexvm-state-probe.log'))
        lines = (args.output / 'guest.log').read_text().splitlines()
        ticks = [int(line.split()[1]) for line in lines if line.startswith('STATE_TICK ')]
        if lines.count('STATE_WORKLOAD_BOOT') != 1 or not ticks or ticks != list(range(ticks[-1] + 1)):
            raise RuntimeError('foreground output rebooted, duplicated or skipped ticks')
        if args.boot != 'app':
            # A deliberately stopped exec service must not prevent the whole
            # distro from restoring or completing a normal OS power-off.
            command = ['systemctl', 'stop', 'flexvm-runtime.service'] if args.boot == 'systemd' else ['rc-service', 'flexvm-runtime', 'stop']
            stopped = cli('exec', NAME, *command, check=False, result=True)
            # The caller occupies the service being stopped. Systemd sends
            # SIGTERM; OpenRC's successful stop hook uses cgroup.kill/SIGKILL.
            stopped_codes = (0, 143) if args.boot == 'systemd' else (0, 137)
            if stopped.returncode not in stopped_codes:
                raise RuntimeError(f'could not stop distro runtime: {stopped.returncode}: {stopped.stderr}')
            cli('pause', NAME)
            cli('unpause', NAME)
            cli('stop', NAME)
            owner.wait(timeout=10)
            ENGINE_GONE(target, deadline)
            with (args.output / 'guest.log').open('a') as out, (args.output / 'restore-no-runtime.log').open('w') as err:
                owner = subprocess.Popen([*base, 'start', '--attach', NAME], stdout=out, stderr=err, env=environment)
            restored = ready()['backend']['process']
            if restored == target:
                raise RuntimeError('distro restoration without runtime service reused its source engine')
            evidence['restore_without_runtime_service'] = {'status': 'passed', 'source_engine': target, 'target_engine': restored}
            target = restored
            # Keep the owned engine's console open across normal owner cleanup.
            with contextlib.ExitStack() as held:
                console = []
                try:
                    proc = Path('/proc') / str(target['pid'])
                    start = int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[19])
                    if start != target['start']:
                        raise RuntimeError('engine identity changed before shutdown diagnostics')
                    words = (proc / 'cmdline').read_bytes().decode().split('\0')
                    qmp = words[words.index('-qmp') + 1]
                    if not qmp.startswith('unix:'):
                        raise RuntimeError('engine QMP socket is not a local path')
                    logs = Path(qmp[5:].split(',', 1)[0]).parent.parent / 'logs'
                    for name in ('qemu.log.1', 'qemu.log'):
                        if (logs / name).exists():
                            console.append(held.enter_context((logs / name).open('rb')))
                except (OSError, ValueError, RuntimeError) as error:
                    (args.output / 'poweroff-console-error.log').write_text(str(error) + '\n')
                started = time.monotonic()
                try:
                    cli('kill', '--signal', 'TERM', NAME)
                    if owner.wait(timeout=min(args.poweroff_timeout, max(.1, deadline - time.monotonic()))) != 0 or cli('wait', NAME).strip() != '0':
                        raise RuntimeError('software distro did not report completed OS poweroff')
                    evidence['poweroff'] = {'owner_status': 0, 'wait_status': 0, 'elapsed_s': round(time.monotonic() - started, 3)}
                finally:
                    (args.output / 'poweroff-console.log').write_bytes(b''.join(stream.read() for stream in console))
        else:
            cli('kill', NAME)
            if cli('wait', NAME).strip() != '130':
                raise RuntimeError('restored VM lost its kill status')
        evidence.update(boot_count=1, process_ticks=len(ticks))
        ENGINE_GONE(target, deadline)
        evidence.update(status='passed', source_engine=source, target_engine=target)
        (args.output / 'owner.json').write_text(json.dumps(evidence, indent=2) + '\n')
    finally:
        try:
            subprocess.run([*base, 'kill', NAME], capture_output=True, timeout=10, env=environment)
        except subprocess.TimeoutExpired:
            pass
        if owner and owner.poll() is None:
            owner.send_signal(signal.SIGINT)
            try:
                owner.wait(timeout=10)
            except subprocess.TimeoutExpired:
                owner.kill()
                owner.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bin', 'kernel', 'workload', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--image', default=IMAGE)
    parser.add_argument('--boot', choices=('app', 'systemd', 'openrc'), default='app')
    parser.add_argument('--mem', type=int, default=2048)
    parser.add_argument('--vcpus', type=int, default=2)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--poweroff-timeout', type=int, default=30, help='bounded OS shutdown wait, within the overall test deadline')
    parser.add_argument('--require', action='append', default=[])
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--state', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.bin, args.kernel, args.workload = (path.resolve(strict=True) for path in (args.bin, args.kernel, args.workload))
    args.output = args.output.resolve()
    if args.worker:
        exercise(args)
        return 0
    if os.geteuid() != 0:
        parser.error('run as root for private device masking and image preparation')
    if not 1 <= args.timeout <= 3600 or not 512 <= args.mem <= 8192 or not 1 <= args.poweroff_timeout <= 300 or not 1 <= args.vcpus <= 8:
        parser.error('--timeout must be 1..3600, --mem 512..8192 and --poweroff-timeout 1..300 and --vcpus 1..8')
    args.output.mkdir(parents=True, exist_ok=True)
    report_path = args.output / 'report.json'
    if report_path.exists():
        parser.error('output already contains a report')
    qemu_name = 'qemu-system-' + platform.machine()
    qemu_path = shutil.which(qemu_name)
    if qemu_path is None:
        parser.error(f'{qemu_name} is required')
    qemu = Path(qemu_path).resolve(strict=True)
    report = {'schema_version': 1, 'status': 'failed', 'arch': platform.machine(), 'accelerator': 'tcg',
              'scope': 'ordinary guest workload through software pause and fresh-owner stop/start',
              'binary_sha256': HELPERS['digest'](args.bin), 'kernel_sha256': HELPERS['digest'](args.kernel),
              'qemu_sha256': HELPERS['digest'](qemu), 'image': args.image, 'boot_profile': args.boot,
              'vcpus': args.vcpus, 'memory_mib': args.mem, 'poweroff_timeout_s': args.poweroff_timeout,
              'workload': {'name': args.workload.name, 'sha256': HELPERS['digest'](args.workload)}}
    started = time.monotonic()
    def interrupted(number, _frame):
        raise HELPERS['Interrupted'](number)
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        report['compiler_version'] = subprocess.check_output(['cc', '--version'], text=True, timeout=10).splitlines()[0]
        report['qemu_version'] = subprocess.check_output([str(qemu), '--version'], text=True, timeout=10).splitlines()[0]
        for name in ('guest-probe', 'state-probe'):
            subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', str(ROOT / (name + '.c')),
                            '-o', str(args.output / name)], check=True, timeout=120)
        report['probe_sha256'] = {name: HELPERS['digest'](args.output / name) for name in ('guest-probe', 'state-probe')}
        with tempfile.TemporaryDirectory(prefix='flexvm-software-workload-', dir='/var/lib') as state:
            mask = args.output / 'unusable-device'
            mask.touch(mode=0o600)
            trace = args.output / 'files.strace'
            command = ['unshare', '--mount', '--propagation', 'private', 'sh', '-ec',
                       'for dev in /dev/kvm /dev/vhost-vsock; do if [ -e "$dev" ]; then mount --bind "$1" "$dev"; fi; done; shift; exec "$@"',
                       'sh', str(mask), 'strace', '-f', '-e', 'trace=file,init_module,finit_module,delete_module', '-o', str(trace),
                       sys.executable, str(Path(__file__).resolve()), '--worker', '--bin', str(args.bin), '--kernel', str(args.kernel),
                       '--workload', str(args.workload), '--image', args.image, '--mem', str(args.mem), '--vcpus', str(args.vcpus), '--output', str(args.output),
                       '--state', state, '--timeout', str(args.timeout), '--boot', args.boot, '--poweroff-timeout', str(args.poweroff_timeout)]
            for required in args.require:
                command.extend(['--require', required])
            try:
                HELPERS['run'](command, args.timeout, args.output / 'worker.log')
            finally:
                try:
                    subprocess.run([str(args.bin), '--state', str(Path(state) / 'state'), '--run', str(Path(state) / 'run'),
                                    'kill', NAME], capture_output=True, timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            for line in trace.open(errors='replace'):
                if any(f'"{device}"' in line for device in ('/dev/kvm', '/dev/vhost-vsock')):
                    raise RuntimeError('host virtualization device accessed; see files.strace')
                if re.match(r'^(?:\d+\s+)?(?:init_module|finit_module|delete_module)\(', line):
                    raise RuntimeError('host kernel module loader invoked; see files.strace')
        report.update(status='passed', owner=json.loads((args.output / 'owner.json').read_text()),
                      kvm_access=False, vhost_vsock_access=False, host_module_loading=False)
    except HELPERS['Interrupted'] as error:
        report.update(status='interrupted', signal=error.number, error=str(error))
    except Exception as error:
        report.update(status='failed', error=str(error))
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    report['elapsed_s'] = round(time.monotonic() - started, 3)
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['status'].upper()}: {report_path}")
    return 128 + report['signal'] if report['status'] == 'interrupted' else (0 if report['status'] == 'passed' else 1)


if __name__ == '__main__':
    raise SystemExit(main())
