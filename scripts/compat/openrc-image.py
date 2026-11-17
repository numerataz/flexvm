#!/usr/bin/env python3
"""Build the OpenRC OCI fixture by installing ordinary packages inside an owned guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import time

IMAGE = 'public.ecr.aws/docker/library/alpine@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2'
PACKAGES = ['openrc', 'openrc-init', 'dbus', 'dbus-openrc', 'eudev', 'udev-init-scripts',
            'python3', 'iproute2', 'procps', 'util-linux']


def prepare(base, name, output, deadline):
    """Export an ordinary OCI layout from an already running, caller-owned guest."""
    def cli(*words, **kwargs):
        return subprocess.run([*base, *words], check=True, timeout=max(.1, deadline - time.monotonic()), **kwargs)

    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        raise ValueError(f'fixture output must be absent or an empty directory: {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    cli('exec', name, 'apk', 'add', '--no-cache', *PACKAGES)
    packages = cli('exec', name, 'apk', 'info', '-v', capture_output=True, text=True).stdout
    print(packages, flush=True)
    cli('exec', name, '/bin/sh', '-ec', 'test -x /sbin/openrc-init; mkdir -p /usr/local/bin /usr/local/sbin')
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
    with tempfile.TemporaryDirectory(prefix='.openrc-image-', dir=output.parent) as temporary:
        layout = Path(temporary) / 'layout'
        blobs = layout / 'blobs' / 'sha256'
        blobs.mkdir(parents=True)
        layer = Path(temporary) / 'layer.tar'
        with layer.open('wb') as destination:
            cli('exec', name, 'tar', '-C', '/', '--exclude=./proc', '--exclude=./sys', '--exclude=./dev',
                '--exclude=./run', '--exclude=./tmp', '--exclude=./etc/flexvm', '--exclude=./sbin/flexvm-init',
                '-cf', '-', '.', stdout=destination)

        def blob(data=None, path=None):
            if path is not None:
                with path.open('rb') as source:
                    digest = hashlib.file_digest(source, 'sha256').hexdigest()
                size = path.stat().st_size
                path.rename(blobs / digest)
            else:
                digest, size = hashlib.sha256(data).hexdigest(), len(data)
                (blobs / digest).write_bytes(data)
            return {'digest': 'sha256:' + digest, 'size': size}

        layer_desc = dict(mediaType='application/vnd.oci.image.layer.v1.tar', **blob(path=layer))
        config = {'architecture': architecture, 'os': 'linux',
                  'config': {'Env': ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']},
                  'rootfs': {'type': 'layers', 'diff_ids': [layer_desc['digest']]}}
        config_desc = dict(mediaType='application/vnd.oci.image.config.v1+json', **blob(json.dumps(config, sort_keys=True).encode()))
        manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                    'config': config_desc, 'layers': [layer_desc]}
        descriptor = dict(mediaType=manifest['mediaType'], **blob(json.dumps(manifest, sort_keys=True).encode()))
        (layout / 'oci-layout').write_text(json.dumps({'imageLayoutVersion': '1.0.0'}))
        (layout / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [descriptor]}))
        (layout / 'fixture.json').write_text(json.dumps({'source': IMAGE, 'packages': packages.splitlines(), 'manifest': descriptor}, indent=2) + '\n')
        os.chmod(layout, 0o755)
        layout.rename(output)
    print(f'OpenRC fixture {descriptor["digest"]}: {output}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    if os.geteuid() != 0 or not 1 <= args.timeout <= 1800:
        parser.error('run as root, with --timeout in 1..1800')
    binary, kernel = args.bin.resolve(strict=True), args.kernel.resolve(strict=True)
    output = args.output.absolute()
    deadline = time.monotonic() + args.timeout

    def interrupted(number, _frame):
        raise KeyboardInterrupt(f'interrupted by signal {number}')

    signal.signal(signal.SIGTERM, interrupted)
    with tempfile.TemporaryDirectory(prefix='flexvm-openrc-fixture-', dir='/var/lib') as temporary:
        state = Path(temporary)
        base = [str(binary), '--state', str(state / 'state'), '--run', str(state / 'run')]
        name = 'openrc-image-builder'
        with (state / 'owner.log').open('w+') as log:
            owner = subprocess.Popen([*base, 'software', '--name', name, '--control', 'serial', '--kernel', str(kernel),
                                      '--mem', '1024', IMAGE, '/bin/sleep', '1800'], stdout=log, stderr=subprocess.STDOUT)
            try:
                while time.monotonic() < deadline:
                    if owner.poll() is not None:
                        raise RuntimeError(f'fixture guest exited: {owner.returncode}')
                    entries = json.loads(subprocess.check_output([*base, 'ps', '--json'], text=True, timeout=10))
                    if any(entry['name'] == name and entry['state'] == 'running' for entry in entries):
                        break
                    time.sleep(.2)
                else:
                    raise TimeoutError('OpenRC fixture guest did not start')
                prepare(base, name, output, deadline)
            except BaseException:
                log.seek(0)
                print(log.read()[-8000:], flush=True)
                raise
            finally:
                blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
                try:
                    try:
                        subprocess.run([*base, 'kill', name], capture_output=True, timeout=15)
                    except subprocess.TimeoutExpired:
                        pass
                    try:
                        owner.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        owner.terminate()
                        owner.wait(timeout=15)
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, blocked)


if __name__ == '__main__':
    main()
