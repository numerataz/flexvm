#!/usr/bin/env python3
"""Verify offline cache trust, corruption rejection and archive boundaries."""
import gzip
import io
import json
from pathlib import Path
import runpy
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HELPER = Path(__file__).with_name('workload-fixture.py')


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / 'cache'
        (self.cache / 'blobs/sha256').mkdir(parents=True)
        self.api = runpy.run_path(str(HELPER))
        self.globals = self.api['prepare'].__globals__
        self.digest = self.api['digest']
        self.payload = b'authenticated uncompressed layer'
        def blob(data):
            name = self.digest(data)
            (self.cache / 'blobs/sha256' / name[7:]).write_bytes(data)
            return dict(digest=name, size=len(data))
        self.config = json.dumps(dict(os='linux', architecture='amd64',
            rootfs=dict(type='layers', diff_ids=[self.digest(self.payload)]))).encode()
        self.config_descriptor = blob(self.config)
        self.layer_descriptor = blob(gzip.compress(self.payload))
        self.manifest = blob(json.dumps(dict(config=self.config_descriptor, layers=[self.layer_descriptor])).encode())
        upstream = json.dumps(dict(manifests=[dict(self.manifest, platform=dict(os='linux', architecture='amd64'))])).encode()
        (self.cache / 'upstream-index.json').write_bytes(upstream)
        (self.cache / 'index.json').write_text(json.dumps(dict(manifests=[self.manifest])))
        self.override = patch.dict(self.globals, PIN=self.digest(upstream))
        self.override.start()
        self.addCleanup(self.override.stop)
        self.archive()

    def archive(self, payload=None, config=None, extra=None):
        files = {'config.json': self.config if config is None else config,
                 'layer.tar': self.payload if payload is None else payload,
                 'manifest.json': json.dumps([dict(Config='config.json', Layers=['layer.tar'], RepoTags=[self.api['TAG']])]).encode()}
        if extra:
            files.update(extra)
        with tarfile.open(self.cache / 'busybox.tar', 'w') as archive:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))

    def prepare(self):
        with patch('subprocess.run', side_effect=AssertionError('external process on cache hit')), \
             patch('subprocess.check_output', side_effect=AssertionError('registry access on cache hit')):
            return self.api['prepare'](self.cache, self.root / 'output', 'amd64')

    def test_valid_cache_works_with_registry_and_converter_unavailable(self):
        identity = self.prepare()
        self.assertEqual(identity['config_digest'], self.config_descriptor['digest'])
        self.assertEqual((self.root / 'output/busybox.tar').read_bytes(), (self.cache / 'busybox.tar').read_bytes())

    def test_changed_pin_blob_and_local_index_are_rejected(self):
        for name in ['upstream-index.json', 'blobs/sha256/' + self.config_descriptor['digest'][7:],
                     'blobs/sha256/' + self.layer_descriptor['digest'][7:], 'index.json']:
            path = self.cache / name
            original = path.read_bytes()
            path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            with self.assertRaises((ValueError, KeyError)):
                self.prepare()
            path.write_bytes(original)

    def test_archive_checks_anchored_config_and_uncompressed_layer(self):
        for changes in [dict(payload=b'forged layer'), dict(config=b'forged config'), dict(extra={'unexpected': b'x'})]:
            self.archive(**changes)
            with self.assertRaises(ValueError):
                self.prepare()

    def test_symlink_and_fifo_cache_entries_are_rejected_without_opening(self):
        link = self.cache / 'external'
        link.symlink_to(self.root / 'not-present')
        with self.assertRaises(ValueError):
            self.prepare()
        link.unlink()
        import os
        os.mkfifo(link)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_lock_symlink_is_never_followed(self):
        (self.root / 'cache.lock').symlink_to(self.root / 'outside')
        with self.assertRaises(OSError):
            self.prepare()
        self.assertFalse((self.root / 'outside').exists())

    def test_wrong_architecture_and_existing_output_are_refused(self):
        with self.assertRaises(ValueError):
            self.api['validate_cache'](self.cache, 'arm64')
        (self.root / 'output').mkdir()
        with self.assertRaises(FileExistsError):
            self.prepare()


    def test_daemon_exports_authenticate_config_and_inflated_oci_layers(self):
        verify = runpy.run_path(str(HELPER.with_name('verify-fixture-import.py')))['verify']
        identity = self.api['validate_cache'](self.cache, 'amd64')
        self.assertEqual(verify(self.cache / 'busybox.tar', identity)['status'], 'passed')
        for payload in (self.payload, b'forged filesystem'):
            layer = gzip.compress(payload)
            descriptor = dict(digest=self.digest(layer), size=len(layer), mediaType='application/vnd.oci.image.layer.v1.tar+gzip')
            manifest = json.dumps(dict(config=self.config_descriptor, layers=[descriptor])).encode()
            manifest_descriptor = dict(digest=self.digest(manifest), size=len(manifest))
            files = {'index.json': json.dumps(dict(manifests=[manifest_descriptor])).encode(),
                     'blobs/sha256/' + manifest_descriptor['digest'][7:]: manifest,
                     'blobs/sha256/' + self.config_descriptor['digest'][7:]: self.config,
                     'blobs/sha256/' + descriptor['digest'][7:]: layer}
            path = self.root / 'daemon.tar'
            with tarfile.open(path, 'w') as archive:
                for name, data in files.items():
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
            if payload == self.payload:
                self.assertEqual(verify(path, identity)['status'], 'passed')
            else:
                with self.assertRaises(ValueError):
                    verify(path, identity)

    def test_daemon_fifo_export_is_rejected_without_opening(self):
        import os
        verify = runpy.run_path(str(HELPER.with_name('verify-fixture-import.py')))['verify']
        fifo = self.root / 'daemon-fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            verify(fifo, {})

    def test_daemon_export_without_an_image_manifest_is_rejected(self):
        verify = runpy.run_path(str(HELPER.with_name('verify-fixture-import.py')))['verify']
        path = self.root / 'incomplete.tar'
        with tarfile.open(path, 'w') as archive:
            entry = tarfile.TarInfo('blobs/sha256/' + self.config_descriptor['digest'][7:])
            entry.size = len(self.config)
            archive.addfile(entry, io.BytesIO(self.config))
        with self.assertRaisesRegex(ValueError, 'missing regular member .*index.json'):
            verify(path, self.api['validate_cache'](self.cache, 'amd64'))


if __name__ == '__main__':
    unittest.main()
