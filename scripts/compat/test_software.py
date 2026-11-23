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
import struct
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


class ParentMemorySlots(unittest.TestCase):
    def test_registration_validates_each_slot_before_mapping(self):
        protocol = runpy.run_path(str(ROOT / "parent-kvm-run.py"))
        mailbox = bytearray(protocol["MAILBOX_SIZE"])
        pages = protocol["RAM_ADDRESS_AT"]
        struct.pack_into("<I", mailbox, 32, 2)
        struct.pack_into("<IIQIIQ", mailbox, 640, 1, 2, 0, 6, 1, 0x8000)
        struct.pack_into("<3Q", mailbox, pages, 0x100000, 0x102000, 0x101000)
        parse = protocol["read_registered_slots"]
        slots = parse(mailbox, 3 * 4096, 3, 2 * 1024 * 1024)
        self.assertEqual([(slot.identifier, slot.gpa, len(slot.offsets)) for slot in slots],
                         [(1, 0, 2), (6, 0x8000, 1)])
        with self.assertRaisesRegex(RuntimeError, "parent memory limit"):
            parse(mailbox, 3 * 4096, 2, 2 * 1024 * 1024)
        struct.pack_into("<Q", mailbox, 664, 0x1000)
        with self.assertRaisesRegex(RuntimeError, "overlapping"):
            parse(mailbox, 3 * 4096, 3, 2 * 1024 * 1024)
        struct.pack_into("<Q", mailbox, 664, 0x8000)
        struct.pack_into("<Q", mailbox, pages + 16, 0x100000)
        with self.assertRaisesRegex(RuntimeError, "outside outer RAM or repeated"):
            parse(mailbox, 3 * 4096, 3, 2 * 1024 * 1024)


class ParentRunLanes(unittest.TestCase):
    def test_parallel_stream_acks_do_not_wait_for_a_second_byte(self):
        protocol = runpy.run_path(str(ROOT / "parent-kvm-run.py"))
        mailbox = bytearray(protocol["MAILBOX_SIZE"])
        stride = protocol["LANE_STRIDE"]
        base = protocol["LANES_AT"]
        cpus = {0, 1}
        replies = os.eventfd(0)
        self.addCleanup(os.close, replies)
        sockets, peers = zip(*(socket.socketpair() for _ in cpus), strict=True)
        for connection in (*sockets, *peers):
            self.addCleanup(connection.close)
            connection.settimeout(.5)
        for peer in peers:
            peer.sendall(b"R")
        lanes = protocol["RunLanes"]([protocol["RunChannel"](sock) for sock in sockets])

        for cpu in cpus:
            struct.pack_into("<III", mailbox, base + cpu * stride, 1, 0, protocol["RUN"])
        lanes.service(mailbox, (), cpus, cpus, replies)
        for cpu, peer in enumerate(peers):
            self.assertEqual(peer.recv(1), bytes((ord("R") + cpu,)))
            peer.sendall(struct.pack("<cBHI", b"V", 1, 0x65 + cpu, 1))
        lanes.service(mailbox, sockets, cpus, cpus, replies)
        self.assertEqual(os.eventfd_read(replies), 2)

        for cpu in cpus:
            offset = base + cpu * stride
            struct.pack_into("<III", mailbox, offset, 2, 1, protocol["COMPLETE_READ"])
            struct.pack_into("<I", mailbox, offset + protocol["LANE_COMPLETION"], 1)
            mailbox[offset + protocol["LANE_PIO"]] = 0x30 + cpu
        lanes.service(mailbox, (), cpus, cpus, replies)
        for cpu, peer in enumerate(peers):
            self.assertEqual(peer.recv(2), bytes((ord("E"), 0x30 + cpu)))
            peer.sendall(b"E")
        lanes.service(mailbox, sockets, cpus, cpus, replies)
        self.assertEqual(os.eventfd_read(replies), 2)
        self.assertFalse(lanes.live)
        self.assertEqual(lanes.max_in_flight, 2)


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

    def test_mask_devices_builds_unshare_wrapper_and_executes_command(self):
        mask_devices = runpy.run_path(str(ROOT / 'software-boot.py'))['mask_devices']
        mask = self.root / 'mask'
        mask.touch()
        trace = self.root / 'files.strace'
        argv = mask_devices(mask, ['echo', 'ok'], devices=('/nonexistent-a', '/nonexistent-b'),
                            trace=trace, trace_events='file,init_module')
        self.assertEqual(argv[:6], ['unshare', '--mount', '--propagation', 'private', 'sh', '-ec'])
        self.assertEqual(argv[argv.index('-e') + 1], 'trace=file,init_module')
        self.assertEqual(argv[argv.index('-o') + 1], str(trace))
        self.assertEqual(argv[-2:], ['echo', 'ok'])
        # Run the sh -ec wrapper directly without unshare/strace using nonexistent paths.
        direct = mask_devices(mask, [sys.executable, '-c', 'import sys; print(",".join(sys.argv[1:]))', 'x', 'y'],
                              devices=('/nonexistent-a', '/nonexistent-b'))
        result = subprocess.run(direct[4:], capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(result.stdout.strip(), 'x,y')

    def test_c_checks_compile_with_strict_warnings(self):
        builds = [
            ('software-init.c', []),
            ('nested-init.c', []),
            ('parent-kvm/init.c', []),
            ('parent-kvm/init.c', ['-DFLEXVM_PARENT_KVM_APP']),
        ]
        if platform.machine() == 'x86_64':
            builds.extend((
                ('kvm-abi.c', []),
                ('kvm-tsc.c', []),
                ('kvm-clock.c', []),
                ('parent-kvm/native-worker.c', []),
            ))
        elif platform.machine() == 'aarch64':
            builds.append(('kvm-arm.c', []))
        for index, (source, flags) in enumerate(builds):
            with self.subTest(source=source, flags=flags):
                subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-pthread',
                                *flags, str(ROOT / source), '-o', str(self.root / f'check-{index}')],
                               check=True, capture_output=True, timeout=60)


class ParentKvmRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='flexvm parent-kvm test ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    @unittest.skipUnless(platform.machine() == 'x86_64', 'native-worker.c is x86_64 only')
    def test_native_worker_monotonic_cancel_and_eintr_retry(self):
        harness = self.root / 'test_native_worker.c'
        binary = self.root / 'test_native_worker'
        harness.write_text('''#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/kvm.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int fake_ioctl(int fd, unsigned long request, ...);
#define ioctl fake_ioctl
#define main native_worker_main
#include "native-worker.c"
#undef main
#undef ioctl

static struct kvm_run *fake_run;
static int kvm_run_calls;
static int scenario;

static void deliver_queue_signal(int value)
{
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    info.si_code = SI_QUEUE;
    info.si_value.sival_int = value;
    interrupt_run(SIGRTMIN, &info, NULL);
}

static int fake_ioctl(int fd, unsigned long request, ...)
{
    (void)fd;
    if (request != KVM_RUN)
        return 0;
    kvm_run_calls++;
    if (scenario == 1) {
        if (kvm_run_calls == 1) {
            deliver_queue_signal(6);
            errno = EINTR;
            return -1;
        }
        assert(cancelled_run == 6);
        assert(fake_run->immediate_exit == 0);
        fake_run->exit_reason = KVM_EXIT_MMIO;
        fake_run->mmio.phys_addr = 0x1000;
        fake_run->mmio.len = 4;
        fake_run->mmio.is_write = 1;
        memset(fake_run->mmio.data, 0x5a, 4);
        return 0;
    }
    if (scenario == 2) {
        deliver_queue_signal(8);
        deliver_queue_signal(6);
        errno = EINTR;
        return -1;
    }
    errno = EINVAL;
    return -1;
}

int main(void)
{
    /* Monotonic cancelled_run must ignore stale older sequence numbers. */
    deliver_queue_signal(5);
    assert(cancelled_run == 5);
    deliver_queue_signal(3);
    assert(cancelled_run == 5);

    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) == 0);

    struct kvm_run run;
    memset(&run, 0, sizeof(run));
    fake_run = &run;
    struct native_lane lane = {
        .control = pair[0],
        .cpu = 42,
        .id = 0,
        .mapping_bytes = (int)sizeof(run),
        .run = &run,
    };

    /* Scenario 1: stale EINTR from sequence 6 during sequence 7 retries KVM_RUN. */
    scenario = 1;
    kvm_run_calls = 0;
    unsigned char req[6] = {'R', 0, 0, 0, 0, 0};
    uint32_t seq = 7;
    memcpy(req + 2, &seq, sizeof(seq));
    serve_cpu_request(&lane, pair[0], req, sizeof(req));
    assert(kvm_run_calls == 2);
    unsigned char reply[32];
    ssize_t n = recv(pair[1], reply, sizeof(reply), 0);
    assert(n == 18 && reply[0] == 'M' && reply[1] == 4);

    /* Scenario 2: cancel for sequence 8 followed by stale sequence 6 reports interrupted. */
    scenario = 2;
    kvm_run_calls = 0;
    seq = 8;
    memcpy(req + 2, &seq, sizeof(seq));
    serve_cpu_request(&lane, pair[0], req, sizeof(req));
    assert(kvm_run_calls == 1);
    assert(cancelled_run == 8);
    n = recv(pair[1], reply, sizeof(reply), 0);
    assert(n == 2 && reply[0] == 'I' && reply[1] == 0);

    close(pair[0]);
    close(pair[1]);
    return 0;
}
''')
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-I', str(ROOT / 'parent-kvm'), str(harness), '-o', str(binary)],
                       check=True, capture_output=True, text=True, timeout=60)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_init_wait_child_reports_exit_status_without_stale_errno(self):
        harness = self.root / 'test_init_wait.c'
        binary = self.root / 'test_init_wait'
        harness.write_text('''#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#define main init_main
#include "init.c"
#undef main

int main(int argc, char **argv)
{
    pid_t child = fork();
    if (child == 0) {
        if (argc > 1 && !strcmp(argv[1], "signal"))
            raise(SIGKILL);
        _exit(7);
    }
    errno = ENOENT;
    wait_child(child, argc > 1 && !strcmp(argv[1], "signal")
               ? "Firecracker exit" : "Firecracker network echo exit");
    return 0;
}
''')
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-DFLEXVM_PARENT_KVM_APP', '-I', str(ROOT / 'parent-kvm'),
                        str(harness), '-o', str(binary)],
                       check=True, capture_output=True, text=True, timeout=60)

        exited = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        self.assertEqual(exited.returncode, 1)
        self.assertIn('FAIL parent KVM setup: Firecracker network echo exit: exited with status 7', exited.stderr)
        self.assertNotIn('No such file or directory', exited.stderr)

        signaled = subprocess.run([str(binary), 'signal'], capture_output=True, text=True, timeout=10)
        self.assertEqual(signaled.returncode, 1)
        self.assertIn('FAIL parent KVM setup: Firecracker exit: terminated by signal 9', signaled.stderr)
        self.assertNotIn('No such file or directory', signaled.stderr)

    def test_firecracker_inner_boot_args_and_echo_timeout(self):
        init_source = (ROOT / 'parent-kvm/init.c').read_text()
        self.assertIn('test_datagram_socket(60)', init_source)
        self.assertNotIn('test_datagram_socket(20)', init_source)
        runner_source = (ROOT / 'parent-kvm-run.py').read_text()
        # Keep `quiet` (loglevel=4 / KERN_WARNING) so nested TCG serial PIO stays fast
        # while kernel warnings, Oops, BUG, and Panic messages still print to ttyS0.
        self.assertIn('"boot_args": "console=ttyS0 quiet panic=1 rdinit=/init reboot=k"', runner_source)


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

    def test_mem_validation_allows_default_zero_and_rejects_out_of_range(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / 'flexvm'
            fake_kernel = root / 'kernel'
            fake_workload = root / 'workload.sh'
            for path in (fake_bin, fake_kernel, fake_workload):
                path.write_bytes(b'fixture')
            output = root / 'output'
            output.mkdir()
            (output / 'report.json').write_text('{}')
            env = dict(os.environ, TEST_ARCH=platform.machine())
            base = [sys.executable, '-c', HELPER, str(ROOT / 'software-workload.py'),
                    '--bin', str(fake_bin), '--kernel', str(fake_kernel),
                    '--workload', str(fake_workload), '--output', str(output)]
            for extra in ([], ['--mem', '0'], ['--mem', '512']):
                with self.subTest(valid=extra):
                    result = subprocess.run(base + extra, env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('output already contains a report', result.stderr)
            for extra in (['--mem', '-1'], ['--mem', '256'], ['--mem', '16384']):
                with self.subTest(invalid=extra):
                    result = subprocess.run(base + extra, env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('--mem 0 or 512..8192', result.stderr)

    def test_failure_prints_report_and_log_tails_to_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / 'bin'
            commands.mkdir()
            arch = platform.machine()
            fake_qemu = commands / f'qemu-system-{arch}'
            fake_qemu.write_text('#!/bin/sh\necho "QEMU emulator version 9.0.0"\n')
            fake_qemu.chmod(0o755)
            fake_cc = commands / 'cc'
            fake_cc.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "cc 1.0"; exit 0; fi\nexit 1\n')
            fake_cc.chmod(0o755)
            fake_bin = root / 'flexvm'
            fake_kernel = root / 'kernel'
            fake_workload = root / 'workload.sh'
            for path in (fake_bin, fake_kernel, fake_workload):
                path.write_bytes(b'fixture')
            output = root / 'output'
            output.mkdir()
            (output / 'owner.log').write_text('owner diagnostic line\n')
            (output / 'workload.log').write_text('X' * 10000 + '\nWORKLOAD_TAIL_MARKER\n')
            env = dict(os.environ, PATH=f'{commands}:{os.environ["PATH"]}', TEST_ARCH=arch)
            argv = [sys.executable, '-c', HELPER, str(ROOT / 'software-workload.py'),
                    '--bin', str(fake_bin), '--kernel', str(fake_kernel),
                    '--workload', str(fake_workload), '--output', str(output)]
            result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn(f'FAILED: {output / "report.json"}', result.stdout)
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertIn('"status": "failed"', result.stderr)
            self.assertIn(report['error'], result.stderr)
            self.assertIn('owner diagnostic line', result.stderr)
            self.assertIn('WORKLOAD_TAIL_MARKER', result.stderr)
            self.assertIn('(last ', result.stderr)


if __name__ == '__main__':
    unittest.main()
