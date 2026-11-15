#!/usr/bin/env python3
"""Run the real software backend with both host virtualization devices masked."""
import argparse
import json
import os
from pathlib import Path
import platform
import runpy
import signal
import time

HELPERS = runpy.run_path(str(Path(__file__).with_name('software-boot.py')))


def descendants(pid):
    pending, found = [pid], set()
    while pending:
        parent = pending.pop()
        try:
            tasks = list(Path(f'/proc/{parent}/task').iterdir())
        except FileNotFoundError:
            continue
        for task in tasks:
            try:
                children = (task / 'children').read_text().split()
            except FileNotFoundError:
                continue
            for child in map(int, children):
                if child not in found:
                    found.add(child)
                    pending.append(child)
    return found


def executable(pid):
    try:
        return os.readlink(f'/proc/{pid}/exe')
    except FileNotFoundError:
        return None


def identity(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
    except FileNotFoundError:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--vsock-backend', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root to mask host devices in a private mount namespace')
    if not 1 <= args.timeout <= 3600:
        parser.error('--timeout must be 1..3600 seconds')
    binary, kernel, backend = (path.resolve(strict=True) for path in (args.bin, args.kernel, args.vsock_backend))
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'report.json'
    if report_path.exists():
        parser.error('output already has a report; use a new directory')
    report = {'schema_version': 1, 'status': 'running', 'scope': 'FlexVM software backend OCI/agent execution',
              'arch': platform.machine(), 'accelerator': 'tcg',
              'binary_sha256': HELPERS['digest'](binary), 'kernel_sha256': HELPERS['digest'](kernel),
              'vsock_backend_sha256': HELPERS['digest'](backend)}
    started = time.monotonic()

    def interrupted(number, _frame):
        raise HELPERS['Interrupted'](number)

    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        mask = out / 'unusable-device'
        mask.touch(mode=0o600)
        trace = out / 'files.strace'
        def isolated(command, trace_path):
            return ['unshare', '--mount', '--propagation', 'private', 'sh', '-ec',
                    'for dev in /dev/kvm /dev/vhost-vsock; do if [ -e "$dev" ]; then mount --bind "$1" "$dev"; fi; done; shift; exec "$@"',
                    'sh', str(mask), 'strace', '-f', '-e', 'trace=file', '-o', str(trace_path), *command]
        # Arguments remain literal argv throughout: none become host shell code.
        check = '''test "$(id -u)" = 1001 && test "$(id -g)" = 1001 &&
 test "$PWD" = /tmp && test "$FLEXVM_CHECK" = software-value &&
 test "$1" = 'literal spaces $HOME *' &&
 printf 'overlay-write' > software-check && test "$(cat software-check)" = overlay-write || exit 19
 echo FLEXVM_SOFTWARE_AGENT_STDOUT
 echo FLEXVM_SOFTWARE_AGENT_STDERR >&2
 exit 7'''
        cmd = [str(binary), 'software', '--kernel', str(kernel), '--vsock-backend', str(backend),
               '--state', str(out / 'state'), '--user', '1001:1001', '--workdir', '/tmp',
               '--env', 'FLEXVM_CHECK=software-value', '--timeout', '90',
               'public.ecr.aws/docker/library/busybox:1.36', '/bin/sh', '-c', check,
               'software-check', 'literal spaces $HOME *']
        wrapped = ['sh', '-c', '"$@"; status=$?; test "$status" -eq 7 || exit 1; echo FLEXVM_SOFTWARE_EXIT_STATUS_PASSED', 'sh', *cmd]
        HELPERS['run'](isolated(wrapped, trace), args.timeout, out / 'guest.log')
        log = (out / 'guest.log').read_text(errors='replace')
        for marker in ('FLEXVM_SOFTWARE_AGENT_STDOUT', 'FLEXVM_SOFTWARE_AGENT_STDERR', 'FLEXVM_SOFTWARE_EXIT_STATUS_PASSED'):
            if marker not in log:
                raise RuntimeError(f'missing {marker}; see guest.log')
        # Signal only the owner, leaving the engines in place for it to clean up.
        # Killing the entire process group here would hide ownership bugs.
        engines = {}
        runtime = []
        cancel_log = out / 'cancel.log'
        def cancel_owner(proc, deadline):
            while 'FLEXVM_SOFTWARE_CANCEL_READY' not in cancel_log.read_text(errors='replace'):
                if proc.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('cancellation workload did not become ready')
                time.sleep(.02)
            owners = [pid for pid in descendants(proc.pid) if executable(pid) == str(binary)]
            if len(owners) != 1:
                raise RuntimeError(f'expected one software VM owner, got {owners}')
            owner = owners[0]
            for pid in descendants(owner):
                engines[pid] = identity(pid)
                argv = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                for i, arg in enumerate(argv[:-1]):
                    if arg == b'-qmp':
                        runtime.append(Path(os.fsdecode(argv[i + 1]).split(',')[0].removeprefix('unix:')).parent)
            if len(engines) < 2 or not runtime:
                raise RuntimeError('did not find both owned engines and the private socket directory')
            os.kill(owner, signal.SIGTERM)

        cancel_cmd = [str(binary), 'software', '--kernel', str(kernel), '--vsock-backend', str(backend),
                      '--state', str(out / 'state'), 'public.ecr.aws/docker/library/busybox:1.36',
                      '/bin/sh', '-c', 'echo FLEXVM_SOFTWARE_CANCEL_READY; sleep 600']
        wrapped = ['sh', '-c', '"$@"; status=$?; test "$status" -eq 143 || exit 1', 'sh', *cancel_cmd]
        cancel_trace = out / 'cancel-files.strace'
        HELPERS['run'](isolated(wrapped, cancel_trace), args.timeout, cancel_log, during=cancel_owner)
        if any(start is not None and identity(pid) == start for pid, start in engines.items()):
            raise RuntimeError('an owned engine survived owner cancellation')
        if any(path.exists() for path in runtime):
            raise RuntimeError('private sockets survived owner cancellation')
        traced = trace.read_text(errors='replace') + cancel_trace.read_text(errors='replace')
        if any(f'"{dev}"' in traced for dev in ('/dev/kvm', '/dev/vhost-vsock')):
            raise RuntimeError('software execution accessed a host virtualization device; see files.strace')
        report.update(status='passed', kvm_access=False, vhost_vsock_access=False,
                      guest_uid=1001, guest_gid=1001, command_exit=7, cancellation='passed')
    except HELPERS['Interrupted'] as exc:
        report.update(status='interrupted', error=str(exc), signal=exc.number)
    except Exception as exc:
        report.update(status='failed', error=str(exc))
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        report['elapsed_s'] = round(time.monotonic() - started, 3)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['status'].upper()}: {report_path}")
    if report['status'] == 'interrupted':
        return 128 + report['signal']
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
