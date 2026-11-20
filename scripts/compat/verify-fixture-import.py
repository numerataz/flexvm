#!/usr/bin/env python3
"""Check a real daemon's exported config and filesystem against a verified fixture."""
import argparse
import gzip
import hashlib
import io
import json
import stat
from pathlib import Path
import tarfile

LIMIT = 64 << 20


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def verify(path, metadata):
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > LIMIT:
        raise ValueError('daemon export exceeds fixture budget')
    with tarfile.open(path, 'r:') as archive:
        files, total = {}, 0
        for entry in archive:
            total += entry.size
            if total > LIMIT or len(files) > 256:
                raise ValueError('daemon export members exceed fixture budget')
            if entry.isfile():
                name = entry.name.removeprefix('./')
                if name in files:
                    raise ValueError('duplicate daemon export member')
                files[name] = entry
        def read(name):
            # No extraction or link following: only regular archive members.
            entry = files.get(name)
            if entry is None:
                raise ValueError(f'daemon export is missing regular member {name!r}')
            return archive.extractfile(entry).read()
        def document(name):
            data = read(name)
            if len(data) > 1 << 20:
                raise ValueError('daemon export JSON exceeds its budget')
            return json.loads(data)
        if 'manifest.json' in files:
            manifests = document('manifest.json')
            if len(manifests) != 1:
                raise ValueError('daemon export contains multiple images')
            manifest = manifests[0]
            config = read(manifest['Config'])
            actual = []
            for name in manifest['Layers']:
                data = read(name)
                # Docker-compatible exports may retain gzip-compressed blobs.
                if data.startswith(b'\x1f\x8b'):
                    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                        data = stream.read(LIMIT + 1)
                    if len(data) > LIMIT:
                        raise ValueError('daemon export layer exceeds its inflated budget')
                actual.append(digest(data))
        else:
            def blob(descriptor):
                data = read('blobs/sha256/' + descriptor['digest'].removeprefix('sha256:'))
                if len(data) != descriptor['size'] or digest(data) != descriptor['digest']:
                    raise ValueError('daemon export descriptor mismatch')
                return data
            index = document('index.json')
            for _ in range(4):
                if len(index['manifests']) != 1:
                    raise ValueError('daemon export does not select one image')
                manifest = json.loads(blob(index['manifests'][0]))
                if 'manifests' not in manifest:
                    break
                index = manifest
            else:
                raise ValueError('nested daemon export indexes')
            config = blob(manifest['config'])
            actual = []
            for descriptor in manifest['layers']:
                data = blob(descriptor)
                if descriptor['mediaType'].endswith(('+gzip', '.gzip')):
                    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                        data = stream.read(LIMIT + 1)
                    if len(data) > LIMIT:
                        raise ValueError('daemon export layer exceeds its inflated budget')
                elif not descriptor['mediaType'].endswith('.tar'):
                    raise ValueError('unsupported daemon export layer format')
                actual.append(digest(data))
        if digest(config) != metadata['config_digest'] or actual != metadata['diff_ids']:
            raise ValueError('daemon changed the authenticated configuration or filesystem')
        config = json.loads(config)
        if config['os'] != 'linux' or config['architecture'] != metadata['architecture']:
            raise ValueError('daemon changed the authenticated architecture')
    return dict(status='passed', config_digest=metadata['config_digest'], diff_ids=actual)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    args = parser.parse_args()
    if not stat.S_ISREG(args.metadata.lstat().st_mode) or args.metadata.stat().st_size > 1 << 20:
        parser.error('fixture metadata exceeds its budget')
    print(json.dumps(verify(args.archive, json.loads(args.metadata.read_text()))))


if __name__ == '__main__':
    main()
