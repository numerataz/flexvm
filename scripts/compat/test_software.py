#!/usr/bin/env python3
"""Software-check cancellation/report contracts with fake tools; no root or VM."""
import json
import os
from pathlib import Path
import platform
import runpy
import signal
import socket
import subprocess
import sys
import tempfile
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
            sources.append('kvm-abi.c')
        elif platform.machine() == 'aarch64':
            sources.append('kvm-arm.c')
        for source in sources:
            with self.subTest(source=source):
                subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-pthread',
                                str(ROOT / source), '-o', str(self.root / source.removesuffix('.c'))],
                               check=True, capture_output=True, timeout=60)


if __name__ == '__main__':
    unittest.main()
