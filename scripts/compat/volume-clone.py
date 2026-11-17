#!/usr/bin/env python3
"""Verify real storage CLI clones with host virtualization devices masked."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1 << 20):
            value.update(chunk)
    return value.hexdigest()


def exercise(args, report):
    root = args.output
    blocked = root / 'blocked-device'
    blocked.touch(mode=0)
    for device in ['/dev/kvm', '/dev/vhost-vsock']:
        if Path(device).exists():
            subprocess.run(['mount', '--bind', str(blocked), device], check=True, timeout=10)
    parent = root
    mounted = False
    child = None
    try:
        if args.btrfs:
            image = root / 'filesystem.btrfs'
            with image.open('xb') as stream:
                stream.truncate(256 << 20)
            subprocess.run(['mkfs.btrfs', '-q', '-f', '-K', str(image)], check=True, timeout=30)
            parent = root / 'mounted'
            parent.mkdir()
            subprocess.run(['mount', '-t', 'btrfs', '-o', 'loop', str(image), str(parent)], check=True, timeout=15)
            mounted = True
        state = parent / 'state'
        sequence = 0

        def cli(*words, success=True):
            nonlocal sequence
            sequence += 1
            trace = root / f'command-{sequence}.strace'
            command = ['strace', '-f', '-yy', '-e', 'trace=file,ioctl,lseek,pread64,pwrite64', '-o', str(trace)]
            if args.scan_fallback:
                command += ['-e', 'inject=ioctl:error=EOPNOTSUPP', '-e', 'inject=lseek:error=EINVAL']
            command += [str(args.bin), '--state', str(state), 'volume', *words]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, start_new_session=True)
            try:
                out, err = process.communicate(timeout=90)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                raise
            report['commands'].append({'argv': list(words), 'status': process.returncode,
                                       'stdout': out, 'stderr': err, 'trace': trace.name})
            if (process.returncode == 0) != success:
                raise RuntimeError(f'{words}: exit {process.returncode}: {err}')
            return json.loads(out) if out.strip() else None

        def raw(info):
            return state / 'volumes' / info['id'] / 'disk.raw'

        size = 16 << 20 if args.scan_fallback else 1 << 30
        original = cli('create', 'source', '--size', str(size))
        source = raw(original)
        with source.open('r+b', buffering=0) as stream:
            os.pwrite(stream.fileno(), b'source-head', 4096)
            os.pwrite(stream.fileno(), b'source-tail', size - 11)
            os.fsync(stream.fileno())
        source_hash = digest(source)
        cloned = cli('clone', original['id'], 'copy')
        copy = raw(cloned)
        clone_trace = (root / f'command-{sequence}.strace').read_text()
        assert cloned['id'] != original['id'] and cloned['capacity_bytes'] == size
        assert source.stat().st_ino != copy.stat().st_ino
        assert source.stat().st_nlink == copy.stat().st_nlink == 1
        assert cloned['allocated_bytes'] < size // 2, cloned
        assert digest(copy) == source_hash
        with copy.open('r+b', buffering=0) as stream:
            assert os.pread(stream.fileno(), 16, size // 2) == bytes(16)
            os.pwrite(stream.fileno(), b'cloned-head', 4096)
            os.fsync(stream.fileno())
        with source.open('r+b', buffering=0) as stream:
            os.pwrite(stream.fileno(), b'changedtail', size - 11)
            os.fsync(stream.fileno())
        with source.open('rb', buffering=0) as stream:
            assert os.pread(stream.fileno(), 11, 4096) == b'source-head'
        with copy.open('rb', buffering=0) as stream:
            assert os.pread(stream.fileno(), 11, size - 11) == b'source-tail'
        with source.open('r+b', buffering=0) as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            child = subprocess.Popen(['sh', '-c', 'printf .; read release'], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, pass_fds=(lease.fileno(),))
            assert select.select([child.stdout], [], [], 5)[0], 'lease child was not ready'
            assert child.stdout.read(1) == b'.'
        cli('clone', 'source', 'blocked-copy', success=False)
        assert len(cli('ls')) == 2
        child.stdin.write(b'release\n')
        child.stdin.flush()
        child.wait(timeout=5)
        child.stdin.close()
        child.stdout.close()
        child = None
        second = cli('clone', 'source', 'second-copy')
        assert second['id'] not in [original['id'], cloned['id']]
        cli('clone', 'source', 'copy', success=False)
        cli('rm', 'source')
        assert cli('inspect', 'copy')['id'] == cloned['id']
        with copy.open('rb', buffering=0) as stream:
            assert os.pread(stream.fileno(), 11, 4096) == b'cloned-head'
        cli('rm', 'copy')
        cli('rm', 'second-copy')
        assert cli('ls') == []
        reflinked = any('FICLONE' in line and re.search(r'= 0$', line) for line in clone_trace.splitlines())
        method = 'reflink' if reflinked else 'copy'
        if args.btrfs:
            assert reflinked, clone_trace
        if args.scan_fallback:
            assert 'FICLONE' in clone_trace and 'EOPNOTSUPP' in clone_trace
            assert 'SEEK_DATA' in clone_trace and 'EINVAL' in clone_trace and 'INJECTED' in clone_trace
            method = 'zero-scan'
        for trace in root.glob('*.strace'):
            text = trace.read_text()
            assert '"/dev/kvm"' not in text and '"/dev/vhost-vsock"' not in text
        report.update(status='passed', method=method, capacity_bytes=size, original_sha256=source_hash,
                      clone_allocated_bytes=cloned['allocated_bytes'], independent_ids=True,
                      independent_writes=True, source_deleted_clone_retained=True,
                      inherited_lease_blocks_clone=True, host_kvm_access=False, host_vsock_access=False)
    finally:
        try:
            if child is not None:
                child.kill()
                child.wait(timeout=5)
                child.stdin.close()
                child.stdout.close()
        finally:
            if mounted:
                subprocess.run(['umount', str(parent)], check=True, timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    cases = parser.add_mutually_exclusive_group()
    cases.add_argument('--btrfs', action='store_true', help='require actual reflinks in an owned loop filesystem')
    cases.add_argument('--scan-fallback', action='store_true', help='inject unsupported clone and extent-query errors')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root to create a private mount namespace')
    if not args.worker:
        os.execvp('unshare', ['unshare', '--mount', '--propagation', 'private', sys.executable,
                             str(Path(__file__).resolve()), '--worker', *sys.argv[1:]])
    args.bin = args.bin.resolve(strict=True)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True)
    started = time.monotonic()
    report = {'status': 'failed', 'binary_sha256': digest(args.bin), 'commands': [],
              'filesystem': 'btrfs' if args.btrfs else 'host', 'forced_scan': args.scan_fallback}
    try:
        exercise(args, report)
    except Exception as error:
        report.update(status='failed', error=f'{type(error).__name__}: {error}')
    finally:
        report['elapsed_s'] = round(time.monotonic() - started, 3)
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['status'].upper()}: {args.output / 'report.json'}")
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
