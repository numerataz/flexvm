#!/usr/bin/env python3
"""Run the ordinary guest KVM API and unchanged Firecracker inside FlexVM TCG."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import runpy
import signal
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parent
HELPERS = runpy.run_path(str(ROOT / 'software-boot.py'))


def image(path, arch, files, entrypoint=None):
    """Docker-save archive with static workloads; the real agent is injected normally."""
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name in ('dev', 'proc', 'sys', 'run', 'tmp', 'etc', 'sbin', 'bin', 'root', 'var'):
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o1777 if name == 'tmp' else 0o755
            tar.addfile(entry)
        for name, (data, mode) in files.items():
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = mode, len(data)
            tar.addfile(entry, io.BytesIO(data))
    config = {'architecture': arch, 'os': 'linux', 'config': {'Entrypoint': entrypoint or ['/kvm-workload']},
              'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(layer.getvalue()).hexdigest()]}}
    manifest = [{'Config': 'config.json', 'RepoTags': ['flexvm-kvm:test'], 'Layers': ['layer.tar']}]
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data in (('config.json', json.dumps(config).encode()), ('layer.tar', layer.getvalue()),
                           ('manifest.json', json.dumps(manifest).encode())):
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = 0o600, len(data)
            tar.addfile(entry, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--firecracker', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args()
    arch = platform.machine()
    if arch not in ('x86_64', 'aarch64'):
        parser.error('this acceptance case supports native x86_64/aarch64')
    if os.geteuid() != 0:
        parser.error('run as root for device masking and OCI preparation')
    if not 1 <= args.timeout <= 3600:
        parser.error('--timeout must be 1..3600 seconds')
    binary, kernel, firecracker = (path.resolve(strict=True) for path in (args.bin, args.kernel, args.firecracker))
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'report.json'
    if report_path.exists():
        parser.error('output already has a report; use a new directory')
    report = {'schema_version': 1, 'status': 'running', 'scope': 'unchanged KVM clients inside FlexVM software execution',
              'arch': arch, 'accelerator': 'tcg', 'control_transport': 'serial',
              'binary_sha256': HELPERS['digest'](binary), 'kernel_sha256': HELPERS['digest'](kernel),
              'firecracker_sha256': HELPERS['digest'](firecracker)}
    started = time.monotonic()

    def interrupted(number, _frame):
        raise HELPERS['Interrupted'](number)

    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    state = None
    try:
        for source, name in (('kvm-abi.c' if arch == 'x86_64' else 'kvm-arm.c', 'kvm-abi'),
                             ('nested-init.c', 'inner-init'), ('kvm-workload.c', 'kvm-workload')):
            HELPERS['run']([args.cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-pthread',
                            str(ROOT / source), '-o', str(out / name)], 60, out / (name + '-compile.log'))
        config = {'boot-source': {'kernel_image_path': '/inner-kernel', 'initrd_path': '/inner-initramfs.cpio',
                                 'boot_args': 'console=ttyS0 quiet panic=1 rdinit=/init' + (' reboot=k' if arch == 'x86_64' else '')},
                  'machine-config': {'vcpu_count': 1, 'mem_size_mib': 128}, 'drives': [], 'network-interfaces': []}
        archive = out / 'image.tar'
        files = {'kvm-workload': ((out / 'kvm-workload').read_bytes(), 0o755),
                 'kvm-abi': ((out / 'kvm-abi').read_bytes(), 0o755), 'firecracker': (firecracker.read_bytes(), 0o755),
                 'inner-kernel': (kernel.read_bytes(), 0o600),
                 'inner-initramfs.cpio': (HELPERS['initramfs']((out / 'inner-init').read_bytes()), 0o600),
                 'firecracker.json': (json.dumps(config).encode(), 0o600),
                 'etc/passwd': (b'root:x:0:0:root:/root:/bin/sh\n', 0o644), 'etc/group': (b'root:x:0:\n', 0o644)}
        image(archive, 'amd64' if arch == 'x86_64' else 'arm64', files)
        report.update(kvm_abi_sha256=HELPERS['digest'](out / 'kvm-abi'), workload_sha256=HELPERS['digest'](out / 'kvm-workload'))
        state = tempfile.TemporaryDirectory(prefix='flexvm-software-kvm-', dir='/var/lib')
        mask = out / 'unusable-device'
        mask.touch(mode=0o600)
        trace = out / 'files.strace'
        cmd = [str(binary), 'software', '--control', 'serial', '--kernel', str(kernel), '--state', state.name,
               '--mem', '512', '--vcpus', '2', str(archive)]
        isolated = ['unshare', '--mount', '--propagation', 'private', 'sh', '-ec',
                    'for dev in /dev/kvm /dev/vhost-vsock; do if [ -e "$dev" ]; then mount --bind "$1" "$dev"; fi; done; shift; exec "$@"',
                    'sh', str(mask), 'strace', '-f', '-e', 'trace=file', '-o', str(trace), *cmd]
        HELPERS['run'](isolated, args.timeout, out / 'guest.log')
        lines = (out / 'guest.log').read_text(errors='replace').splitlines()
        markers = ('FLEXVM_SOFTWARE_KVM_API_PASSED', 'FLEXVM_SOFTWARE_INNER_BOOTED',
                   *(f'FLEXVM_SOFTWARE_INNER_TICK {i}' for i in range(3)),
                   'FLEXVM_SOFTWARE_INNER_COMPLETE', 'FLEXVM_SOFTWARE_KVM_FIRECRACKER_PASSED')
        positions = []
        for marker in markers:
            if lines.count(marker) != 1:
                raise RuntimeError(f'expected one {marker}; see guest.log')
            positions.append(lines.index(marker))
        if positions != sorted(positions):
            raise RuntimeError('nested execution markers are out of order; see guest.log')
        if any('Kernel panic' in line or 'Oops:' in line for line in lines):
            raise RuntimeError('guest kernel failed; see guest.log')
        abi_marker = 'PASS: 10 KVM ABI reference checks' if arch == 'x86_64' else 'FLEXVM_SOFTWARE_GUEST_KVM_PASSED'
        if abi_marker not in lines:
            raise RuntimeError('missing successful KVM ABI report; see guest.log')
        traced = trace.read_text(errors='replace')
        if any(f'"{dev}"' in traced for dev in ('/dev/kvm', '/dev/vhost-vsock')):
            raise RuntimeError('host virtualization device access; see files.strace')
        report.update(status='passed', guest_kvm_api='passed', guest_firecracker='passed',
                      inner_timer_ticks=3, inner_stop='i8042-reset' if arch == 'x86_64' else 'psci-poweroff',
                      kvm_access=False, vhost_vsock_access=False)
    except HELPERS['Interrupted'] as exc:
        report.update(status='interrupted', signal=exc.number, error=str(exc))
    except Exception as exc:
        report.update(status='failed', error=str(exc))
    finally:
        if state is not None:
            state.cleanup()
        for number, handler in previous.items():
            signal.signal(number, handler)
        report['elapsed_s'] = round(time.monotonic() - started, 3)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['status'].upper()}: {report_path}")
    return 128 + report['signal'] if report['status'] == 'interrupted' else (0 if report['status'] == 'passed' else 1)


if __name__ == '__main__':
    raise SystemExit(main())
