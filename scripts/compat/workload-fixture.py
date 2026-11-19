#!/usr/bin/env python3
"""Cache a pinned BusyBox OCI image and export a verified Docker import archive."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

SOURCE = 'public.ecr.aws/docker/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
PIN = SOURCE.split('@')[1]
UBUNTU = 'docker.io/library/ubuntu@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8'
ALPINE = 'docker.io/library/alpine@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2'
TAG = 'docker.io/flexvm/busybox:compat'
LIMIT = 64 << 20


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def document(data):
    if len(data) > 1 << 20:
        raise ValueError('fixture JSON exceeds 1 MiB')
    return json.loads(data)


def checked_blob(root, descriptor):
    name, size = descriptor['digest'], descriptor['size']
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', name) or not isinstance(size, int) or not 0 <= size <= LIMIT:
        raise ValueError('invalid fixture descriptor')
    path = root / 'blobs' / 'sha256' / name[7:]
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size != size:
        raise ValueError('fixture blob is not a regular file of the expected size')
    data = path.read_bytes()
    if digest(data) != name:
        raise ValueError('fixture blob digest mismatch')
    return data


def validate_cache(root, arch, source=SOURCE):
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('fixture cache must be a directory')
    total, count = 0, 0
    for path in root.rglob('*'):
        info = path.lstat()
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('fixture cache contains a link or special file')
        total += info.st_size
        count += 1
        if total > LIMIT or count > 128:
            raise ValueError('fixture cache exceeds its budget')
    upstream = (root / 'upstream-index.json').read_bytes()
    pin = PIN if source == SOURCE else source.split('@')[1]
    if digest(upstream) != pin:
        raise ValueError('fixture upstream index differs from the pinned digest')
    index = document(upstream)
    matches = [item for item in index['manifests'] if item.get('platform', {}).get('os') == 'linux'
               and item['platform'].get('architecture') == arch
               and item['platform'].get('variant', '') in ('', 'v8')]
    if len(matches) != 1:
        raise ValueError('fixture index has no unique native Linux manifest')
    selected = matches[0]
    manifest = document(checked_blob(root, selected))
    config = document(checked_blob(root, manifest['config']))
    if (config['os'], config['architecture']) != ('linux', arch):
        raise ValueError('fixture configuration architecture mismatch')
    layers, diff_ids = manifest['layers'], config['rootfs']['diff_ids']
    if not 1 <= len(layers) <= 8 or len(layers) != len(diff_ids):
        raise ValueError('fixture layer count mismatch')
    for layer, diff_id in zip(layers, diff_ids):
        checked_blob(root, layer)
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', diff_id):
            raise ValueError('invalid fixture diff ID')
    local = document((root / 'index.json').read_bytes())
    if len(local['manifests']) != 1 or local['manifests'][0]['digest'] != selected['digest']:
        raise ValueError('fixture OCI layout points at a different image')
    if local['manifests'][0]['size'] != selected['size']:
        raise ValueError('fixture OCI layout descriptor size differs')
    return dict(source=source, architecture=arch, manifest_digest=selected['digest'],
                config_digest=manifest['config']['digest'], diff_ids=diff_ids,
                **({'tag': TAG} if source == SOURCE else {}))


def validate_archive(path, identity):
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > LIMIT:
        raise ValueError('fixture import archive exceeds its budget or is not regular')
    with tarfile.open(path, 'r:') as archive:
        entries, total = {}, 0
        for entry in archive:
            name = PurePosixPath(entry.name)
            if name.is_absolute() or '..' in name.parts or str(name) in entries or not entry.isfile():
                raise ValueError('invalid fixture archive member')
            total += entry.size
            if total > LIMIT or len(entries) >= 128:
                raise ValueError('fixture archive members exceed their budget')
            entries[str(name)] = entry
        def read(name):
            return archive.extractfile(entries[name]).read()
        manifest = document(read('manifest.json'))
        if len(manifest) != 1 or manifest[0].get('RepoTags') != [TAG]:
            raise ValueError('fixture import archive has unexpected images or tags')
        image = manifest[0]
        if set(entries) != {'manifest.json', image['Config'], *image['Layers']}:
            raise ValueError('fixture archive contains unreferenced payloads')
        if digest(read(image['Config'])) != identity['config_digest']:
            raise ValueError('fixture import configuration differs from the pinned image')
        if len(image['Layers']) != len(identity['diff_ids']):
            raise ValueError('fixture import layer count mismatch')
        for name, expected in zip(image['Layers'], identity['diff_ids']):
            if digest(read(name)) != expected:
                raise ValueError('fixture import layer differs from the pinned diff ID')
    return digest(path.read_bytes())



def canonical_archive(source, target):
    # Skopeo also writes legacy v1 aliases containing symlinks. Keep only the
    # v2 manifest and its regular payloads; never follow or extract those aliases.
    if source.stat().st_size > LIMIT:
        raise ValueError('converted fixture archive exceeds its budget')
    with tarfile.open(source, 'r:') as archive:
        members = archive.getmembers()
        if len(members) > 128 or len({item.name for item in members}) != len(members):
            raise ValueError('converted fixture archive has too many or duplicate members')
        manifest_entry = archive.getmember('manifest.json')
        if not manifest_entry.isfile() or manifest_entry.size > 1 << 20:
            raise ValueError('invalid converted fixture manifest')
        data = archive.extractfile(manifest_entry).read()
        manifest = document(data)
        if len(manifest) != 1:
            raise ValueError('converted fixture contains multiple images')
        names = [manifest[0]['Config'], *manifest[0]['Layers'], 'manifest.json']
        total = 0
        with tarfile.open(target, 'w', format=tarfile.USTAR_FORMAT) as output:
            for name in names:
                path = PurePosixPath(name)
                entry = archive.getmember(name)
                total += entry.size
                if path.is_absolute() or '..' in path.parts or not entry.isfile() or total > LIMIT:
                    raise ValueError('invalid converted fixture payload')
                canonical = tarfile.TarInfo(name)
                canonical.mode, canonical.size = 0o444, entry.size
                output.addfile(canonical, archive.extractfile(entry))


def prepare(cache, output, arch, source=SOURCE):
    pin = PIN if source == SOURCE else source.split('@')[1]
    cache.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(cache.parent / (cache.name + '.lock'), os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not cache.exists():
            with tempfile.TemporaryDirectory(prefix='.' + cache.name + '-', dir=cache.parent) as temporary:
                stage = Path(temporary) / 'oci'
                upstream = subprocess.check_output(['skopeo', 'inspect', '--raw', 'docker://' + source], timeout=120)
                if digest(upstream) != pin:
                    raise ValueError('downloaded fixture index differs from the pin')
                subprocess.run(['skopeo', 'copy', '--preserve-digests', '--override-os', 'linux', '--override-arch', arch,
                                'docker://' + source, f'oci:{stage}:fixture'], check=True, timeout=180)
                (stage / 'upstream-index.json').write_bytes(upstream)
                validate_cache(stage, arch, source)
                stage.rename(cache)
        identity = validate_cache(cache, arch, source)
        if output is None:
            return identity
        exported = cache / 'busybox.tar'
        if not exported.exists():
            temporary = cache / 'export.partial'
            raw = cache / 'raw.partial'
            try:
                subprocess.run(['skopeo', 'copy', f'oci:{cache}:fixture', f'docker-archive:{raw}:{TAG}'],
                               check=True, timeout=120)
                canonical_archive(raw, temporary)
                validate_archive(temporary, identity)
                temporary.rename(exported)
            finally:
                temporary.unlink(missing_ok=True)
                raw.unlink(missing_ok=True)
        identity['archive_sha256'] = validate_archive(exported, identity)[7:]
        output.mkdir(parents=True, exist_ok=False)
        shutil.copyfile(exported, output / 'busybox.tar')
        (output / 'busybox.json').write_text(json.dumps(identity, indent=2) + '\n')
        return identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output', type=Path, help='directory for the BusyBox Docker archive and metadata')
    mode.add_argument('--ubuntu', action='store_const', const=UBUNTU, dest='source', help='prepare a verified Ubuntu OCI layout')
    mode.add_argument('--alpine', action='store_const', const=ALPINE, dest='source', help='prepare a verified Alpine OCI layout')
    parser.add_argument('--arch', choices=('amd64', 'arm64'),
                        default={'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine()))
    args = parser.parse_args()
    if args.arch is None:
        parser.error('native x86_64 or aarch64 is required')
    try:
        print(json.dumps(prepare(args.cache.absolute(), args.output, args.arch, args.source or SOURCE), indent=2))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, f'fixture preparation failed: {error}\n')


if __name__ == '__main__':
    main()
