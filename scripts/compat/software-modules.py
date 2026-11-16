#!/usr/bin/env python3
"""Compile, load and restore guest modules through the normal software CLI."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
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
# Immutable multi-architecture indexes; FlexVM selects and verifies its own architecture.
COMPILER = 'public.ecr.aws/docker/library/gcc@sha256:8c0fe724784c6d617cb582f79ddaf5dd2233aaba2fb7a14e0b9d03348fea8088'
BUSYBOX = 'public.ecr.aws/docker/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
MODULE_NAMES = ('flexvm_test_device', 'flexvm_test_state')


def guest_setup():
    commands = ['set -eux', 'mkdir -p /module-work']
    sources = [(ROOT / 'modules' / name, '/module-work/' + name)
               for name in ('Makefile', 'dkms.conf', 'flexvm_test_state.c', 'flexvm_test_device.c')]
    sources.append((ROOT / 'state-probe.c', '/state-probe.c'))
    for index, (source, destination) in enumerate(sources):
        text = source.read_text()
        marker = f'FLEXVM_MODULE_SOURCE_{index}'
        if marker in text:
            raise RuntimeError('source contains its shell heredoc delimiter')
        commands.append(f"cat > {destination} <<'{marker}'\n{text}\n{marker}")
    commands.append(r'''
cc -std=c11 -O2 -Wall -Wextra -Werror /state-probe.c -o /state-probe
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends kmod dwarves dkms
release=$(uname -r)
make -C /lib/modules/$release/build M=/module-work modules
make -C /lib/modules/$release/build M=/module-work modules_install
depmod -a
printf 'vermagic=0.0.0-flexvm-incompatible\0license=GPL\0name=flexvm_test_state\0' > /tmp/mismatch-modinfo
objcopy --update-section .modinfo=/tmp/mismatch-modinfo /module-work/flexvm_test_state.ko /tmp/mismatched.ko
if /sbin/insmod /tmp/mismatched.ko; then exit 72; fi
test ! -d /sys/module/flexvm_test_state
dmesg | grep '0.0.0-flexvm-incompatible'
echo FLEXVM_MODULE_ABI_MISMATCH_REJECTED
mkdir -p /usr/src/flexvm-compat-fixture-1.0
cp /module-work/*.c /module-work/Makefile /module-work/dkms.conf /usr/src/flexvm-compat-fixture-1.0/
dkms add -m flexvm-compat-fixture -v 1.0
dkms build -m flexvm-compat-fixture -v 1.0 -k "$release"
# The manual build validates ordinary kbuild installation; remove its copies
# before DKMS installation so DKMS cannot legitimately skip identical modules.
rm /lib/modules/$release/extra/flexvm_test_state.ko /lib/modules/$release/extra/flexvm_test_device.ko
depmod -a
dkms install -m flexvm-compat-fixture -v 1.0 -k "$release"
modinfo -F filename flexvm_test_device | grep /updates/dkms/
echo FLEXVM_MODULE_DKMS_BUILD_INSTALL_PASSED
modprobe flexvm_test_device
cat /dev/flexvm-module-test
if rmmod flexvm_test_state; then exit 71; fi
rmmod flexvm_test_device
rmmod flexvm_test_state
test ! -e /dev/flexvm-module-test
test ! -d /sys/module/flexvm_test_state
test ! -d /sys/module/flexvm_test_device
modprobe flexvm_test_device
cat /dev/flexvm-module-test
echo FLEXVM_MODULE_GUEST_COMPILE_AND_DEPENDENCY_PASSED
exec /state-probe
''')
    return '\n'.join(commands)


def engine_gone(identity, deadline):
    try:
        descriptor = os.pidfd_open(identity['pid'])
    except ProcessLookupError:
        return
    try:
        try:
            fields = Path(f'/proc/{identity["pid"]}/stat').read_text().rsplit(')', 1)[1].split()
        except FileNotFoundError:
            return
        if int(fields[19]) != identity['start']:
            return
        waiter = select.poll()
        waiter.register(descriptor, select.POLLIN)
        if not waiter.poll(max(1, int(min(5, deadline - time.monotonic()) * 1000))):
            raise RuntimeError('source engine thread group survived stop')
    finally:
        os.close(descriptor)


def exercise(args):
    deadline = time.monotonic() + args.timeout
    base = [str(args.bin), '--state', str(args.state / 'state'), '--run', str(args.state / 'run')]
    environment = os.environ.copy()
    auth = args.output / 'anonymous-auth'
    auth.mkdir(mode=0o700)
    environment['DOCKER_CONFIG'] = str(auth)
    name = 'module-test'
    owner = None
    evidence = {}

    def cli(*words, check=True):
        result = subprocess.run([*base, *words], capture_output=True, text=True, env=environment,
                                timeout=max(.1, deadline - time.monotonic()))
        if check and result.returncode:
            raise RuntimeError(f'{words[:4]}: exit {result.returncode}: {result.stdout} {result.stderr}')
        return result.stdout if check else result

    def entry():
        return next((item for item in json.loads(cli('ps', '--json')) if item['name'] == name), None)

    def module():
        values = [int(value) for value in cli('exec', name, '/bin/cat', '/dev/flexvm-module-test').split()]
        if len(values) != 2:
            raise RuntimeError(f'invalid kernel module observation: {values}')
        return values

    def advancing_module(before):
        initial = module()
        until = min(deadline, time.monotonic() + 8)
        while time.monotonic() < until:
            time.sleep(.2)
            seen = module()
            if initial[0] != before[0] or seen[0] != before[0]:
                raise RuntimeError('kernel module reloaded or lost its random RAM cookie')
            if seen[1] >= initial[1] + 2 and seen[1] > before[1]:
                return seen
        raise RuntimeError('kernel module timer did not make fresh post-resume progress')

    def process():
        values = [int(value) for value in cli('exec', name, '/state-probe', 'status').split()]
        if len(values) != 5:
            raise RuntimeError(f'invalid userspace observation: {values}')
        return values

    def advancing_process(before):
        initial = process()
        until = min(deadline, time.monotonic() + 8)
        while time.monotonic() < until:
            time.sleep(.2)
            seen = process()
            if initial[:3] != before[:3] or seen[:3] != before[:3]:
                raise RuntimeError('userspace PID/start time/random RAM changed')
            if seen[3] > initial[3] and seen[4] > initial[4] and seen[3] > before[3]:
                return seen
        raise RuntimeError('userspace workload did not make fresh post-resume progress')

    try:
        for module_name in MODULE_NAMES:
            if Path('/sys/module', module_name).exists():
                raise RuntimeError('test module is loaded on the host')
        # Bundle/kernel mismatch must fail before preparing an image or starting an engine.
        mismatch = args.output / 'mismatched-kernel'
        shutil.copyfile(args.kernel, mismatch)
        with mismatch.open('r+b') as stream:
            first = stream.read(1)
            stream.seek(0)
            stream.write(bytes([first[0] ^ 1]))
        refused = cli('software', '--name', 'module-refused', '--control', 'serial', '--kernel', str(mismatch),
                      '--kernel-modules', str(args.sdk), COMPILER, check=False)
        if refused.returncode == 0 or 'does not match the selected kernel' not in refused.stderr:
            raise RuntimeError(f'kernel mismatch was not refused at bundle admission: {refused.stderr}')
        if any(item['name'] == 'module-refused' for item in json.loads(cli('ps', '--json'))):
            raise RuntimeError('mismatched kernel published a VM')
        evidence['mismatch_admission'] = 'passed'
        # A normal app gets the small runtime bundle without the development SDK.
        runtime = r'''release=$(uname -r)
test -f /usr/lib/flexvm/kernel-modules.json
test ! -e /lib/modules/$release/build
grep '"development": false' /usr/lib/flexvm/kernel-modules.json
echo FLEXVM_RUNTIME_MODULES_WITHOUT_SDK_PASSED'''
        cli('software', '--control', 'serial', '--kernel', str(args.kernel), '--mem', '256',
            '--entrypoint', '[]', BUSYBOX, '/bin/sh', '-ec', runtime)
        evidence['runtime_without_sdk'] = 'passed'
        selection = ['--kernel-sdk'] if args.sdk == args.kernel.with_name('kernel-sdk.tar.gz') else ['--kernel-modules', str(args.sdk)]
        with (args.output / 'guest.log').open('w') as output, (args.output / 'owner.log').open('w') as error:
            owner = subprocess.Popen([*base, 'software', '--name', name, '--control', 'serial', '--kernel', str(args.kernel),
                                      '--mem', '1024', '--timeout', '120', *selection, '--entrypoint', '[]', COMPILER,
                                      '/bin/sh', '-ec', guest_setup()], stdout=output, stderr=error, env=environment)
        while 'STATE_WORKLOAD_BOOT' not in (args.output / 'guest.log').read_text(errors='replace'):
            if owner.poll() is not None:
                raise RuntimeError(f'owner exited {owner.returncode}; see owner.log and guest.log')
            if time.monotonic() >= deadline:
                raise TimeoutError('guest compilation did not complete')
            time.sleep(.2)
        output = (args.output / 'guest.log').read_text()
        for marker in ('FLEXVM_MODULE_ABI_MISMATCH_REJECTED', 'FLEXVM_MODULE_DKMS_BUILD_INSTALL_PASSED',
                       'FLEXVM_MODULE_GUEST_COMPILE_AND_DEPENDENCY_PASSED'):
            if marker not in output.splitlines():
                raise RuntimeError(f'missing {marker}')
        manifest = json.loads(cli('exec', name, '/bin/cat', '/usr/lib/flexvm/kernel-modules.json'))
        if manifest['kernel_sha256'] != HELPERS['digest'](args.kernel) or manifest['development'] is not True:
            raise RuntimeError('guest did not receive its matching development bundle')
        evidence.update(guest_kernel=cli('exec', name, '/bin/uname', '-r').strip(),
                        guest_compiler=cli('exec', name, '/usr/local/bin/gcc', '--version').splitlines()[0], manifest=manifest)
        before = module()
        before_process = process()
        cli('pause', name)
        if entry()['state'] != 'paused':
            raise RuntimeError('pause did not fence the outer VM')
        cli('unpause', name)
        before = advancing_module(before)
        before_process = advancing_process(before_process)
        source = entry()['backend']['process']
        cli('stop', name)
        owner.wait(timeout=10)
        engine_gone(source, deadline)
        with (args.output / 'guest.log').open('a') as output, (args.output / 'restore.log').open('w') as error:
            owner = subprocess.Popen([*base, 'start', '--attach', name], stdout=output, stderr=error, env=environment)
        while time.monotonic() < deadline:
            if owner.poll() is not None:
                raise RuntimeError(f'restored owner exited {owner.returncode}; see restore.log')
            restored = entry()
            if restored and restored['state'] == 'running':
                break
            time.sleep(.1)
        else:
            raise TimeoutError('restored owner did not publish')
        target = restored['backend']['process']
        after = advancing_module(before)
        after_process = advancing_process(before_process)
        if source == target:
            raise RuntimeError('restore did not use a fresh emulator process')
        lines = (args.output / 'guest.log').read_text().splitlines()
        ticks = [int(line.split()[1]) for line in lines if line.startswith('STATE_TICK ')]
        if lines.count('STATE_WORKLOAD_BOOT') != 1 or not ticks or ticks != list(range(ticks[-1] + 1)):
            raise RuntimeError('foreground workload booted again, duplicated output or skipped ticks')
        refused = cli('exec', name, '/sbin/rmmod', 'flexvm_test_state', check=False)
        if refused.returncode == 0:
            raise RuntimeError('a module with a live dependent was unloaded')
        for module_name in MODULE_NAMES:
            cli('exec', name, '/sbin/rmmod', module_name)
            cli('exec', name, '/usr/bin/test', '!', '-d', '/sys/module/' + module_name)
        cli('exec', name, '/usr/bin/test', '!', '-e', '/dev/flexvm-module-test')
        cli('exec', name, '/sbin/modprobe', 'flexvm_test_device')
        reloaded = module()
        if reloaded[0] == before[0]:
            raise RuntimeError('module reload did not create a fresh random identity')
        reloaded_after = advancing_module(reloaded)
        cli('kill', name)
        if cli('wait', name).strip() != '130':
            raise RuntimeError('restored VM lost its kill status')
        engine_gone(target, deadline)
        for module_name in MODULE_NAMES:
            if Path('/sys/module', module_name).exists():
                raise RuntimeError('test module appeared on the host')
        evidence.update(status='passed', before=before, after=after, before_process=before_process,
                        after_process=after_process, reloaded=reloaded, reloaded_after=reloaded_after,
                        source_engine=source, target_engine=target)
        (args.output / 'owner.json').write_text(json.dumps(evidence, indent=2) + '\n')
    finally:
        try:
            subprocess.run([*base, 'kill', name], capture_output=True, timeout=5, env=environment)
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
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--sdk', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--state', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.bin, args.kernel = (path.resolve(strict=True) for path in (args.bin, args.kernel))
    args.sdk = (args.sdk or args.kernel.with_name('kernel-sdk.tar.gz')).resolve(strict=True)
    args.output = args.output.resolve()
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
        parser.error('output already has a report; use a new directory')
    started = time.monotonic()
    report = {'schema_version': 1, 'status': 'failed', 'arch': platform.machine(),
              'scope': 'guest module compilation/DKMS and loaded kernel state through software lifecycle',
              'binary_sha256': HELPERS['digest'](args.bin), 'kernel_sha256': HELPERS['digest'](args.kernel),
              'sdk_sha256': HELPERS['digest'](args.sdk), 'compiler_image': COMPILER}
    def interrupted(number, _frame):
        raise HELPERS['Interrupted'](number)
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        with tempfile.TemporaryDirectory(prefix='flexvm-software-modules-', dir='/var/lib') as state:
            mask = args.output / 'unusable-device'
            mask.touch(mode=0o600)
            trace = args.output / 'files.strace'
            command = ['unshare', '--mount', '--propagation', 'private', 'sh', '-ec',
                       'for dev in /dev/kvm /dev/vhost-vsock; do if [ -e "$dev" ]; then mount --bind "$1" "$dev"; fi; done; shift; exec "$@"',
                       'sh', str(mask), 'strace', '-f', '-e', 'trace=file,init_module,finit_module,delete_module', '-o', str(trace),
                       sys.executable, str(Path(__file__).resolve()), '--worker', '--bin', str(args.bin), '--kernel', str(args.kernel),
                       '--sdk', str(args.sdk), '--output', str(args.output), '--state', state, '--timeout', str(args.timeout)]
            try:
                HELPERS['run'](command, args.timeout, args.output / 'worker.log')
            finally:
                # The test owns this private state. Reap its named VM even if
                # the worker was interrupted before its own finally completed.
                try:
                    subprocess.run([str(args.bin), '--state', str(Path(state) / 'state'), '--run', str(Path(state) / 'run'),
                                    'kill', 'module-test'], capture_output=True, timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            for line in trace.open(errors='replace'):
                if any(f'"{device}"' in line for device in ('/dev/kvm', '/dev/vhost-vsock')):
                    raise RuntimeError('host virtualization device access; see files.strace')
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
