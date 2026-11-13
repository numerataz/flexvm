#!/usr/bin/env python3
"""Compatibility harness ownership, failure and cancellation contracts. No VM or root needed."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "compat.py"
spec = importlib.util.spec_from_file_location("compat", SCRIPT)
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)

FAKE = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['TRACE'], 'a') as out:
    out.write(json.dumps(args) + '\n')
while args and args[0] in ('--state', '--run'):
    args = args[2:]
state_path = Path(os.environ['STATE_FILE'])
state = json.loads(state_path.read_text()) if state_path.exists() else {}
verb = args[0]
if verb == 'pull':
    if os.environ.get('FAIL_PULL'): sys.exit(17)
    state['image'] = args[args.index('--tag') + 1]
elif verb == 'cp' and os.environ.get('FAIL_COPY'):
    sys.exit(19)
elif verb == 'checkpoint':
    if args[1] == 'create':
        if os.environ.get('FAIL_CP_BEFORE_CREATE'): sys.exit(20)
        state.setdefault('checkpoints', []).append(args[3])
        if os.environ.get('FAIL_CP_AFTER_CREATE'):
            state_path.write_text(json.dumps(state))
            sys.exit(21)
    elif args[1] == 'ls':
        name = args[-1].split('=', 1)[1]
        print('\n'.join(n for n in state.get('checkpoints', []) if n == name))
    elif args[1] == 'rm':
        state['checkpoints'].remove(args[2])
elif verb == 'run':
    state['name'] = args[args.index('--name') + 1]
    state['active'] = True
elif verb == 'ps':
    print(json.dumps([{'name': state['name']}] if state.get('active') else []))
elif verb == 'rm':
    if os.environ.get('FAIL_RM'): sys.exit(18)
    state['active'] = False
elif verb == 'rmi':
    state['image'] = None
elif verb == 'exec' and any(a.startswith('/tmp/flexvm-probe-') for a in args) and 'if [ -e' not in ' '.join(args):
    if os.environ.get('DELAY_PROBE'): time.sleep(30)
    print(json.dumps({'schema_version': 1, 'probes': [
        {'name': 'kernel.memfd', 'status': 'supported', 'errno': 0},
        {'name': 'virtualization.kvm', 'status': 'missing', 'errno': 2}]}))
state_path.write_text(json.dumps(state))
'''


class Harness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="flexvm compat test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake = self.root / "fake flexvm"
        self.fake.write_text(FAKE)
        self.fake.chmod(0o755)
        self.probe = self.root / "guest probe"
        self.probe.write_text("fixture")
        self.trace = self.root / "trace"
        self.env = dict(os.environ, TRACE=str(self.trace), STATE_FILE=str(self.root / "state"))
        self.output = self.root / "report"
        self.argv = [sys.executable, str(SCRIPT), "--bin", str(self.fake), "--state", "/state with spaces",
                     "--probe-binary", str(self.probe), "--case", "capabilities", "--output", str(self.output)]

    def run_suite(self, *args, **env):
        return subprocess.run(self.argv + list(args), env=dict(self.env, **env), capture_output=True, text=True, timeout=15)

    def calls(self):
        return [json.loads(line)[2:] for line in self.trace.read_text().splitlines()]

    def report(self):
        return json.loads((self.output / "report.json").read_text())

    def test_inventory_reports_optional_gaps_and_cleans_only_its_owned_resources(self):
        result = self.run_suite()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self.report()
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['phases'][0]['capabilities']['probes'][1]['status'], 'missing')
        removed = [c for c in self.calls() if c[0] in ('rm', 'rmi')]
        self.assertEqual(removed, [['rm', '-f', report['vm']], ['rmi', report['vm'] + '-image']])

    def test_required_capability_failure_is_not_a_skip_and_still_cleans_up(self):
        result = self.run_suite('--require', 'virtualization.kvm')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.report()['phases'][0]['status'], 'failed')
        self.assertIn('virtualization.kvm', self.report()['error'])
        self.assertIn('rmi', [c[0] for c in self.calls()])

    def test_borrowed_vm_is_not_stopped_removed_or_rebuilt(self):
        result = self.run_suite('--vm', 'existing')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(set(c[0] for c in self.calls()) & {'pull', 'run', 'stop', 'rm', 'rmi', 'checkpoint'})
        self.assertEqual(self.calls()[-1][0:5], ['exec', '-u', '0', 'existing', 'sh'])

    def test_invalid_borrowed_lifecycle_is_rejected_before_any_command(self):
        result = self.run_suite('--vm', 'existing', '--phases', 'run,suspend')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.trace.exists())

    def test_failed_pull_does_not_remove_an_existing_vm(self):
        result = self.run_suite(FAIL_PULL='1')
        self.assertEqual(result.returncode, 1)
        self.assertEqual([c[0] for c in self.calls()], ['pull', 'logs'])

    def test_borrowed_cleanup_before_copy_preserves_interruption(self):
        args = compat.parse_args(['--vm', 'existing', '--bin', str(self.fake), '--output', str(self.root)])
        suite = compat.Suite(args, self.root)
        suite.report['status'] = 'interrupted'
        suite.cleanup()
        self.assertEqual(suite.report['status'], 'interrupted')
        self.assertEqual(suite.report['cleanup_errors'], [])
        self.assertFalse(self.trace.exists())

    def test_borrowed_copy_failure_conditionally_cleans_only_its_helper(self):
        result = self.run_suite('--vm', 'existing', FAIL_COPY='1')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.report()['cleanup_errors'], [])
        self.assertEqual(self.calls()[-1][0:5], ['exec', '-u', '0', 'existing', 'sh'])

    def test_published_checkpoint_is_cleaned_if_creation_reports_failure(self):
        result = self.run_suite('--phases', 'run,checkpoint', FAIL_CP_AFTER_CREATE='1')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.report()['cleanup_errors'], [])
        self.assertTrue(any(c[:2] == ['checkpoint', 'rm'] for c in self.calls()))
        self.assertEqual(json.loads((self.root / 'state').read_text())['checkpoints'], [])

    def test_unpublished_checkpoint_is_not_removed_if_creation_fails(self):
        result = self.run_suite('--phases', 'run,checkpoint', FAIL_CP_BEFORE_CREATE='1')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.report()['cleanup_errors'], [])
        self.assertFalse(any(c[:2] == ['checkpoint', 'rm'] for c in self.calls()))

    def test_cleanup_failure_fails_the_run(self):
        result = self.run_suite(FAIL_RM='1')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.report()['status'], 'failed')
        self.assertTrue(self.report()['cleanup_errors'])

    def test_checkpoint_is_removed_after_restored_vm_before_image(self):
        result = self.run_suite('--phases', 'run,suspend,checkpoint')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([p['phase'] for p in self.report()['phases']], ['run', 'suspend', 'checkpoint'])
        calls = self.calls()
        final = [c[0:2] for c in calls if c[0] in ('rm', 'rmi') or c[:2] == ['checkpoint', 'rm']][-3:]
        self.assertEqual(final[0], ['rm', '-f'])
        self.assertEqual(final[1], ['checkpoint', 'rm'])
        self.assertEqual(final[2][0], 'rmi')

    def test_sigterm_writes_interrupted_report_and_cleans_up(self):
        proc = subprocess.Popen(self.argv, env=dict(self.env, DELAY_PROBE='1'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.trace.exists() and any(c[0] == 'exec' for c in self.calls()):
                    break
                time.sleep(.02)
            else:
                self.fail('probe did not start')
            proc.send_signal(signal.SIGTERM)
            out, err = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 130, out + err)
            self.assertEqual(self.report()['status'], 'interrupted')
            self.assertIn('rmi', [c[0] for c in self.calls()])
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    def test_command_timeout_kills_descendants(self):
        marker = self.root / "survivor"
        child = 'import time,pathlib; time.sleep(.7); pathlib.Path(' + repr(str(marker)) + ').touch()'
        parent = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",' + repr(child) + ']); time.sleep(10)'
        with self.assertRaises(subprocess.TimeoutExpired):
            compat.command([sys.executable, '-c', parent], timeout=.2)
        time.sleep(.8)
        self.assertFalse(marker.exists())


class Probe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="flexvm-probe-test-")
        cls.binary = Path(cls.temp.name) / "guest-probe"
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
                        str(SCRIPT.parent / 'compat/guest-probe.c'), '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_unprivileged_syscalls_and_json(self):
        for probe in ('kernel.memfd', 'kernel.pidfd', 'security.seccomp'):
            result = subprocess.run([str(self.binary), probe], capture_output=True, text=True, check=True, timeout=10)
            report = json.loads(result.stdout)
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(report['probes'][0]['name'], probe)
            self.assertEqual(report['probes'][0]['status'], 'supported', report)

    def test_unknown_probe_is_an_error_not_an_empty_success(self):
        result = subprocess.run([str(self.binary), 'typo'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
