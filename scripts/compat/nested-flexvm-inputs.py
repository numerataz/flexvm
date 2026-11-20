#!/usr/bin/env python3
"""Build the tiny child OCI image consumed by workloads/nested-flexvm.sh."""
import argparse
import platform
from pathlib import Path
import runpy
import subprocess

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if arch is None:
        parser.error('requires native x86_64 or aarch64')
    args.output.mkdir(parents=True, exist_ok=False)
    probe = args.output / 'state-probe'
    subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
                    str(ROOT / 'state-probe.c'), '-o', str(probe)], check=True, timeout=120)
    runpy.run_path(str(ROOT / 'software-kvm.py'))['image'](args.output / 'child.tar', arch, {
        'state-probe': (probe.read_bytes(), 0o755),
        'etc/passwd': (b'root:x:0:0:root:/root:/bin/sh\n', 0o644),
        'etc/group': (b'root:x:0:\n', 0o644),
    }, ['/state-probe'])


if __name__ == '__main__':
    main()
