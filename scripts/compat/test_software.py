#!/usr/bin/env python3
"""Software-check cancellation/report contracts with fake tools; no root or VM."""
import json
import io
import os
from pathlib import Path
import platform
import runpy
import signal
import socket
import subprocess
import sys
import tempfile
import tarfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent
FAKE_CC = '''#!/usr/bin/env python3
from pathlib import Path
import sys
Path(sys.argv[-1]).write_bytes(b'unit test init fixture')
'''
FAKE_UNSHARE = '''#!/usr/bin/env python3
import os, subprocess, sys, time
from pathlib import Path
trace = Path(sys.argv[sys.argv.index('-o') + 1])
trace.write_text('openat(AT_FDCWD, "/dev/kvm", O_RDWR) = -1\\n' if os.environ.get('MODE') == 'kvm' else '')
if os.environ.get('MODE') == 'hang':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    Path(os.environ['CHILD_PID']).write_text(str(child.pid))
    time.sleep(60)
print('FLEXVM_SOFTWARE_GUEST_BOOTED')
for i in range(3): print('FLEXVM_SOFTWARE_GUEST_TICK', i)
print('FLEXVM_SOFTWARE_GUEST_COMPLETE')
if os.environ.get('MODE') == 'nested':
    print('FLEXVM_SOFTWARE_GUEST_KVM_PASSED')
    print('FLEXVM_SOFTWARE_GUEST_FIRECRACKER_PASSED')
    print('FLEXVM_SOFTWARE_INNER_BOOTED')
    for i in range(3): print('FLEXVM_SOFTWARE_INNER_TICK', i)
    print('FLEXVM_SOFTWARE_INNER_COMPLETE')
'''
HELPER = '''import os, platform, runpy, sys
from unittest.mock import patch
script = sys.argv.pop(1)
platform.machine = lambda: os.environ['TEST_ARCH']
with patch('os.geteuid', return_value=0):
    runpy.run_path(script, run_name='__main__')
'''


class SoftwareCheck(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='flexvm software test ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        commands = self.root / 'bin'
        commands.mkdir()
        for name, source in [('cc', FAKE_CC), ('unshare', FAKE_UNSHARE)]:
            path = commands / name
            path.write_text(source)
            path.chmod(0o755)
        self.kernel = self.root / 'kernel'
        self.kernel.write_bytes(b'unit test kernel fixture')
        self.output = self.root / 'output'
        self.child_pid = self.root / 'child.pid'
        self.env = dict(os.environ, PATH=f'{commands}:{os.environ["PATH"]}', CHILD_PID=str(self.child_pid),
                        TEST_ARCH=platform.machine())
        self.argv = [sys.executable, '-c', HELPER, str(ROOT / 'software-boot.py'),
                     '--kernel', str(self.kernel), '--output', str(self.output)]

    def report(self):
        return json.loads((self.output / 'report.json').read_text())

    def assert_child_stopped(self):
        pid = int(self.child_pid.read_text())
        try:
            state = Path(f'/proc/{pid}/stat').read_text().split()[2]
        except FileNotFoundError:
            return
        self.assertEqual(state, 'Z', 'emulator descendant was left running')

    def test_report_and_existing_output_protection(self):
        result = subprocess.run(self.argv, env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.report()['status'], 'passed')
        self.assertFalse(self.report()['kvm_access'])
        self.assertEqual(self.report()['scope'], 'execution-engine boot only')
        original = (self.output / 'report.json').read_bytes()
        result = subprocess.run(self.argv, env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual((self.output / 'report.json').read_bytes(), original)

    def test_kvm_access_is_a_failure_even_with_all_guest_markers(self):
        result = subprocess.run(self.argv, env=dict(self.env, MODE='kvm'), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.report()['status'], 'failed')
        self.assertIn('access /dev/kvm', self.report()['error'])

    def test_nested_hypervisor_requires_inner_progress_and_records_binary(self):
        firecracker = self.root / 'firecracker'
        firecracker.write_bytes(b'unit test hypervisor fixture')
        argv = self.argv + ['--guest-kvm', '--guest-firecracker', str(firecracker)]
        result = subprocess.run(argv, env=dict(self.env, TEST_ARCH='aarch64', MODE='nested'),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.report()['scope'], 'software guest hypervisor execution')
        self.assertTrue(self.report()['guest_firecracker'])
        self.assertIn('firecracker_sha256', self.report())
        self.output = self.root / 'missing-inner'
        argv[argv.index('--output') + 1] = str(self.output)
        result = subprocess.run(argv, env=dict(self.env, TEST_ARCH='aarch64'),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.report()['status'], 'failed')

    def test_timeout_stops_descendants_and_preserves_failed_report(self):
        result = subprocess.run(self.argv + ['--timeout', '1'], env=dict(self.env, MODE='hang'),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.report()['status'], 'failed')
        self.assert_child_stopped()

    def test_checkpoint_qmp_timeout_stops_emulator_descendants(self):
        firecracker = self.root / 'firecracker'
        firecracker.write_bytes(b'unit test hypervisor fixture')
        argv = self.argv + ['--guest-kvm', '--guest-firecracker', str(firecracker), '--checkpoint', '--timeout', '1']
        result = subprocess.run(argv, env=dict(self.env, TEST_ARCH='aarch64', MODE='hang'),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.report()['status'], 'failed')
        self.assertIn('timed out', self.report()['error'])
        self.assert_child_stopped()
        self.assertFalse((self.output / 'checkpoint').exists())

    def test_qmp_skips_events_and_rejects_command_errors(self):
        qmp_class = runpy.run_path(str(ROOT / 'software-boot.py'))['QMP']
        path = self.root / 'qmp'
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(str(path))
        server.listen(1)
        errors = []

        def serve():
            try:
                server.settimeout(3)
                conn, _ = server.accept()
                with conn, conn.makefile('rwb', buffering=0) as stream:
                    conn.settimeout(3)
                    stream.write(b'{"QMP": {}}\n')
                    self.assertEqual(json.loads(stream.readline())['execute'], 'qmp_capabilities')
                    stream.write(b'{"event":"STOP"}\n{"return":{}}\n')
                    self.assertEqual(json.loads(stream.readline())['execute'], 'query-status')
                    stream.write(b'{"error":{"desc":"intentional rejection"}}\n')
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        qmp = qmp_class(path, None, time.monotonic() + 3)
        try:
            with self.assertRaisesRegex(RuntimeError, 'intentional rejection'):
                qmp.ask('query-status')
        finally:
            qmp.close()
            worker.join(timeout=4)
        self.assertFalse(worker.is_alive())
        if errors:
            raise errors[0]

    def test_sigterm_stops_descendants_and_records_interruption(self):
        proc = subprocess.Popen(self.argv, env=dict(self.env, MODE='hang'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not self.child_pid.exists() and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(self.child_pid.exists(), 'fake emulator did not start')
            proc.send_signal(signal.SIGTERM)
            _, err = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 143, err)
            self.assertEqual(self.report()['status'], 'interrupted')
            self.assert_child_stopped()
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate()

    def test_c_checks_compile_with_strict_warnings(self):
        sources = ['software-init.c', 'nested-init.c']
        if platform.machine() == 'x86_64':
            sources.extend(('kvm-abi.c', 'kvm-tsc.c', 'kvm-clock.c'))
        elif platform.machine() == 'aarch64':
            sources.append('kvm-arm.c')
        for source in sources:
            with self.subTest(source=source):
                subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-pthread',
                                str(ROOT / source), '-o', str(self.root / source.removesuffix('.c'))],
                               check=True, capture_output=True, timeout=60)


class LifecycleFailureState(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='flexvm lifecycle failure ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'fixture'
        (self.state / 'state/suspended/test').mkdir(parents=True)
        self.out = self.root / 'evidence'
        self.out.mkdir()
        self.capture = runpy.run_path(str(ROOT / 'software-lifecycle.py'))['retain_failed_state']

    def report(self):
        return json.loads((self.out / 'failure-state.json').read_text())

    def test_sparse_state_and_external_link_are_retained_without_following(self):
        directory = self.state / 'state/suspended/test'
        (directory / 'manifest.json').write_text('{"fixture": true}')
        with (directory / 'state').open('wb') as stream:
            stream.seek(64 << 20)
            stream.write(b'checkpoint tail')
        cache = self.state / 'state/images'
        cache.mkdir()
        with (cache / 'unused').open('wb') as stream:
            stream.truncate((2 << 30) + 1)
        (directory / 'external').symlink_to(self.root / 'missing-outside-target')
        self.capture(self.state, self.out)
        report = self.report()
        self.assertEqual(report['status'], 'captured', report)
        raw = subprocess.check_output(['zstd', '-dc', str(self.out / report['archive'])], timeout=5)
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            self.assertFalse(any(name.startswith('state/images') for name in archive.getnames()))
            link = archive.getmember('state/suspended/test/external')
            self.assertTrue(link.issym())
            self.assertEqual(archive.extractfile('state/suspended/test/manifest.json').read(), b'{"fixture": true}')
            stream = archive.extractfile('state/suspended/test/state')
            stream.seek(64 << 20)
            self.assertEqual(stream.read(), b'checkpoint tail')
        self.assertLess(report['bytes'], 1 << 20)

    def test_special_files_and_oversize_state_fail_without_an_archive(self):
        fifo = self.state / 'state/fifo'
        os.mkfifo(fifo)
        self.capture(self.state, self.out)
        self.assertIn('special file', self.report()['error'])
        self.assertFalse((self.out / 'failure-state.tar.zst').exists())
        fifo.unlink()
        (self.out / 'failure-state.json').unlink()
        with (self.state / 'state/oversize').open('wb') as stream:
            stream.truncate((2 << 30) + 1)
        self.capture(self.state, self.out)
        self.assertIn('logical budget', self.report()['error'])
        self.assertFalse((self.out / 'failure-state.tar.zst').exists())


class WorkloadSeeds(unittest.TestCase):
    def test_rejects_special_oversized_and_escaping_inputs_before_reading(self):
        seed = runpy.run_path(str(ROOT / 'software-workload.py'))['seed_files']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / 'payload'
            file.write_bytes(b'payload')
            self.assertEqual(seed([(str(file), '/nested-input/a b')]), [(file, '/nested-input/a b')])
            for target in ['/etc/payload', '/nested-input/../etc/payload', '/nested-input/']:
                with self.assertRaises(ValueError):
                    seed([(str(file), target)])
            with self.assertRaises(ValueError):
                seed([(str(file), '/nested-input/a'), (str(file), '/nested-input/a')])
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                seed([(str(fifo), '/nested-input/fifo')])
            with file.open('wb') as stream:
                stream.truncate(256 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                seed([(str(file), '/nested-input/large')])


if __name__ == '__main__':
    unittest.main()
