#!/usr/bin/env python3
"""Native block confinement oracle; does not implement managed VM attachments."""
import argparse
import ctypes
import contextlib
import fcntl
import http.client
import json
import os
from pathlib import Path
import re
import runpy
import select
import signal
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

HELPERS = runpy.run_path(str(Path(__file__).with_name('software-boot.py')))


class Engine:
    def __init__(self, binary, disk, output, runtime, label, deadline):
        self.deadline = deadline
        self.api = runtime / (label + '.sock')
        self.log = output / (label + '.log')
        self.trace = output / (label + '.strace')
        self.pidfd = None
        self.process = None
        self.console = self.log.open('w')
        parent = os.getpid()
        libc = ctypes.CDLL(None, use_errno=True)

        def guard():
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
                os._exit(127)

        try:
            self.process = subprocess.Popen([
                'strace', '--kill-on-exit', '-ff', '-yy', '-e', 'trace=openat,fsync,fdatasync,pwrite64',
                '-o', str(self.trace), str(binary), '--api-sock', str(self.api)],
                stdin=subprocess.PIPE, stdout=self.console, stderr=subprocess.STDOUT,
                pass_fds=(disk.fileno(),), preexec_fn=guard, cwd=output)
            while True:
                self.remaining()
                if self.process.poll() is not None:
                    raise RuntimeError(f'{label}: VMM exited before publishing its API')
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(self.remaining())
                    try:
                        probe.connect(str(self.api))
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        time.sleep(.01)
            children = Path(f'/proc/{self.process.pid}/task/{self.process.pid}/children').read_text().split()
            candidates = []
            for child in children:
                try:
                    if os.path.samestat(os.stat(f'/proc/{child}/exe'), binary.stat()):
                        candidates.append(int(child))
                except FileNotFoundError:
                    continue
            if len(candidates) != 1:
                raise RuntimeError(f'{label}: cannot identify owned VMM: {candidates}')
            self.pid = candidates[0]
            self.pidfd = os.pidfd_open(self.pid)
            inherited = os.stat(f'/proc/{self.pid}/fd/{disk.fileno()}')
            fdinfo = Path(f'/proc/{self.pid}/fdinfo/{disk.fileno()}').read_text()
            if not os.path.samestat(inherited, os.fstat(disk.fileno())) or 'FLOCK' not in fdinfo:
                raise RuntimeError(f'{label}: VMM did not inherit the actual disk lease')
        except BaseException:
            self.close()
            raise

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('native block restore deadline')
        return left

    def request(self, method, path, value, expect=204):
        connection = http.client.HTTPConnection('localhost', timeout=self.remaining())
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stream.settimeout(self.remaining())
        try:
            stream.connect(str(self.api))
            connection.sock = stream
            connection.request(method, path, json.dumps(value), {'Content-Type': 'application/json'})
            response = connection.getresponse()
            data = response.read().decode(errors='replace')
            if response.status != expect:
                raise RuntimeError(f'{method} {path}: HTTP {response.status}: {data}')
            return data
        finally:
            connection.close()
            stream.close()

    def marker(self, pattern):
        while True:
            match = re.search(pattern, self.log.read_text(errors='replace'))
            if match:
                return match
            self.remaining()
            if self.process.poll() is not None:
                raise RuntimeError(f'VMM exited before {pattern}')
            time.sleep(.01)

    def send(self, token):
        self.process.stdin.write(token)
        self.process.stdin.flush()

    def snapshot(self, state, memory):
        self.request('PATCH', '/vm', {'state': 'Paused'})
        self.request('PUT', '/snapshot/create', {'snapshot_type': 'Full', 'snapshot_path': str(state), 'mem_file_path': str(memory)})

    def close(self):
        try:
            if self.pidfd is not None:
                poll = select.poll()
                poll.register(self.pidfd, select.POLLIN)
                if not poll.poll(0):
                    signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                    if not poll.poll(5000):
                        raise RuntimeError('owned VMM did not retire')
            elif self.process is not None and self.process.poll() is None:
                self.process.kill()
            if self.process is not None:
                self.process.wait(timeout=5)
                if self.process.stdin:
                    self.process.stdin.close()
        finally:
            if self.pidfd is not None:
                os.close(self.pidfd)
                self.pidfd = None
            self.console.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firecracker', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--serial', default='fv0123456789abcdef01')
    args = parser.parse_args()
    args.firecracker = args.firecracker.resolve(strict=True)
    args.kernel = args.kernel.resolve(strict=True)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True)
    report = {'schema_version': 1, 'status': 'failed', 'scope': 'native raw block confinement and fresh-VMM snapshot restore',
              'managed_volumes': False, 'flexvm_lifecycle': False,
              'firecracker_sha256': HELPERS['digest'](args.firecracker), 'kernel_sha256': HELPERS['digest'](args.kernel)}
    started = time.monotonic()
    engines = []
    nonce = uuid.uuid4().hex
    seed, marker, after = [value.encode() for value in (f'SEED {nonce}', f'BEFORE_RESTORE {nonce}', f'AFTER_RESTORE {nonce}')]
    source = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>
static const char seed[] = @SEED@;
static const char marker[] = @MARKER@;
static const char after[] = @AFTER@;
static const char serial[] = @SERIAL@;
static int gate(char expected) {
    char token[2];
    for (int n = 0; n < 2;) {
        ssize_t got = read(0, token + n, 2 - n);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        n += got;
    }
    return token[0] == expected && token[1] == '\n' ? 0 : -1;
}
static int check_serial(void) {
    int fd = open("/sys/block/vda/serial", O_RDONLY);
    char seen[64] = {0};
    if (fd < 0 || read(fd, seen, sizeof(seen) - 1) <= 0) return -1;
    close(fd); seen[strcspn(seen, "\n")] = 0;
    return strcmp(seen, serial);
}
int main(void) {
    if (getpid() != 1) return 2;
    int console = open("/dev/console", O_RDWR);
    if (console < 0) return 2;
    for (int i = 0; i < 3; i++) if (dup2(console, i) < 0) return 2;
    if (console > 2) close(console);
    setvbuf(stdout, NULL, _IONBF, 0);
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755")) goto fail;
    if (mkdir("/sys", 0755) && errno != EEXIST) goto fail;
    if (mount("sysfs", "/sys", "sysfs", MS_NOSUID, 0)) goto fail;
    int fd = -1;
    for (int i = 0; i < 100 && fd < 0; i++) { fd = open("/dev/vda", O_RDWR); if (fd < 0) usleep(20000); }
    if (fd < 0 || check_serial()) goto fail;
    char seen[sizeof(marker)] = {0};
    if (pread(fd, seen, sizeof(seed) - 1, 0) != sizeof(seed) - 1 || memcmp(seen, seed, sizeof(seed) - 1)) goto fail;
    uint64_t cookie = 0;
    int random = open("/dev/urandom", O_RDONLY);
    if (random < 0 || read(random, &cookie, sizeof(cookie)) != sizeof(cookie)) goto fail;
    close(random);
    volatile unsigned counter = 0;
    printf("REFERENCE_READY %016llx\n", (unsigned long long)cookie);
    if (gate('W')) goto fail;
    counter++;
    if (pwrite(fd, marker, sizeof(marker) - 1, 4096) != sizeof(marker) - 1 || fsync(fd)) goto fail;
    printf("CHECKPOINT_READY %016llx %u\n", (unsigned long long)cookie, counter);
    if (gate('R') || counter != 1 || check_serial() || ioctl(fd, BLKFLSBUF)) goto fail;
    if (pread(fd, seen, sizeof(marker) - 1, 4096) != sizeof(marker) - 1 || memcmp(seen, marker, sizeof(marker) - 1)) goto fail;
    if (pwrite(fd, after, sizeof(after) - 1, 8192) != sizeof(after) - 1 || fsync(fd)) goto fail;
    counter++;
    printf("RESTORE_RAM_OK %016llx %u\n", (unsigned long long)cookie, counter);
    close(fd);
    reboot(RB_POWER_OFF);
fail:
    perror("native-block-restore");
    for (;;) pause();
}
'''
    for token, value in {'@SEED@': seed.decode(), '@MARKER@': marker.decode(), '@AFTER@': after.decode(), '@SERIAL@': args.serial}.items():
        source = source.replace(token, json.dumps(value))
    try:
        cfile, binary = args.output / 'init.c', args.output / 'init'
        cfile.write_text(source)
        with (args.output / 'compile.log').open('w') as log:
            subprocess.run(['cc', '-static', '-Os', '-Wall', '-Wextra', '-Werror', str(cfile), '-o', str(binary)], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
        disk_path = args.output / 'disk-0'
        with contextlib.ExitStack() as stack:
            disk = stack.enter_context(disk_path.open('x+b'))
            temporary = stack.enter_context(tempfile.TemporaryDirectory(prefix='fvblkr-'))
            disk.truncate(16 << 20)
            disk.write(seed)
            disk.flush()
            os.fsync(disk.fileno())
            fcntl.flock(disk, fcntl.LOCK_EX | fcntl.LOCK_NB)
            runtime = Path(temporary)
            archive = runtime / 'init.cpio'
            archive.write_bytes(HELPERS['initramfs'](binary.read_bytes()))
            deadline = time.monotonic() + 60
            def engine(label):
                value = Engine(args.firecracker, disk, args.output, runtime, label, deadline)
                engines.append(value)
                stack.callback(value.close)
                return value
            original = engine('source')
            original.request('PUT', '/boot-source', {'kernel_image_path': str(args.kernel), 'initrd_path': str(archive), 'boot_args': 'console=ttyS0 quiet panic=1 rdinit=/init'})
            original.request('PUT', '/machine-config', {'vcpu_count': 1, 'mem_size_mib': 256})
            original.request('PUT', '/drives/data', {'drive_id': 'data', 'serial': args.serial, 'path_on_host': 'disk-0', 'is_root_device': False, 'is_read_only': False, 'io_engine': 'Sync', 'cache_type': 'Writeback'})
            original.request('PUT', '/actions', {'action_type': 'InstanceStart'})
            cookie = original.marker(r'REFERENCE_READY ([0-9a-f]{16})\n')[1]
            reference, reference_mem = args.output / 'reference.vmstate', args.output / 'reference.memory'
            original.snapshot(reference, reference_mem)
            original.request('PATCH', '/vm', {'state': 'Resumed'})
            original.send(b'W\n')
            original.marker(r'CHECKPOINT_READY ' + cookie + r' 1\n')
            checkpoint, memory = args.output / 'checkpoint.vmstate', args.output / 'checkpoint.memory'
            original.snapshot(checkpoint, memory)
            os.fsync(disk.fileno())
            original.close()
            binding = {'drive_id': 'data', 'serial': args.serial, 'path_on_host': 'disk-0', 'capacity_bytes': 16 << 20, 'is_read_only': False, 'is_root_device': False}
            load = {'snapshot_path': str(checkpoint), 'mem_backend': {'backend_type': 'File', 'backend_path': str(memory)}, 'resume_vm': False, 'confined_blocks': [binding]}
            no_reference = engine('missing-reference')
            error = no_reference.request('PUT', '/snapshot/load', load, expect=400)
            if 'trusted device reference' not in error:
                raise RuntimeError(f'missing reference was not rejected: {error}')
            no_reference.close()
            traces = ''.join(path.read_text(errors='replace') for path in args.output.glob('missing-reference.strace.*'))
            if 'openat(AT_FDCWD, "disk-0"' in traces:
                raise RuntimeError('missing-reference restore opened the disk alias')
            load['device_reference_path'] = str(reference)
            disk.truncate(8 << 20)
            os.fsync(disk.fileno())
            bad_geometry = engine('wrong-geometry')
            error = bad_geometry.request('PUT', '/snapshot/load', load, expect=400)
            if 'confined backing' not in error.lower():
                raise RuntimeError(f'backing geometry was not rejected: {error}')
            bad_geometry.close()
            disk.truncate(16 << 20)
            os.fsync(disk.fileno())
            # Model a transferred image: the fresh VMM opens a new inode through
            # the same caller-defined slot, while the retired source stays leased.
            source_disk = disk
            source_identity = os.fstat(source_disk.fileno())
            incoming = args.output / 'incoming.raw'
            copied = stack.enter_context(incoming.open('x+b'))
            source_disk.seek(0)
            shutil.copyfileobj(source_disk, copied)
            copied.flush()
            os.fsync(copied.fileno())
            fcntl.flock(copied, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if os.fstat(copied.fileno()).st_ino == source_identity.st_ino:
                raise RuntimeError('transferred disk did not get an independent inode')
            disk_path.rename(args.output / 'source-retired.raw')
            incoming.rename(disk_path)
            directory = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            disk = copied
            restored = engine('restored')
            restored.request('PUT', '/snapshot/load', load)
            restored.request('PATCH', '/vm', {'state': 'Resumed'})
            restored.send(b'R\n')
            restored.marker(r'RESTORE_RAM_OK ' + cookie + r' 2\n')
            code = restored.process.wait(timeout=restored.remaining())
            restored.close()
            console = restored.log.read_text(errors='replace')
            if code != 0 or 'Kernel panic' in console or 'REFERENCE_READY' in console or 'reboot: Power down' not in console:
                raise RuntimeError(f'restored guest did not continue and power off: {code}')
            disk.seek(4096)
            if disk.read(len(marker)) != marker:
                raise RuntimeError('pre-checkpoint disk marker changed')
            disk.seek(8192)
            if disk.read(len(after)) != after:
                raise RuntimeError('restored VMM did not flush its new disk write')
            source_disk.seek(8192)
            if source_disk.read(len(after)) != bytes(len(after)):
                raise RuntimeError('fresh VMM modified the retired source backing')
            flush = re.compile(r'(?:fsync|fdatasync)\(\d+<' + re.escape(str(disk_path)) + r'>\)\s*= 0')
            for label in ['source', 'restored']:
                if not any(flush.search(path.read_text(errors='replace')) for path in args.output.glob(label + '.strace.*')):
                    raise RuntimeError(f'{label} did not flush the selected host backing file')
            report.update(status='passed', snapshot_restore=True, ram_cookie=cookie, counter=2, source_retired=True, inherited_vmm_lease=True,
                          missing_reference_refused_before_disk_open=True, backing_geometry_refused=True, host_backing_flush=True,
                          restored_status=code, backing_inode_changed=True, retired_source_unchanged=True, disk_sha256=HELPERS['digest'](disk_path), checkpoint_sha256=HELPERS['digest'](checkpoint), reference_sha256=HELPERS['digest'](reference))
    except Exception as error:
        report['error'] = str(error)
    finally:
        for engine in reversed(engines):
            try:
                engine.close()
            except Exception as error:
                report.setdefault('cleanup_errors', []).append(str(error))
                report['status'] = 'failed'
        report['elapsed_s'] = round(time.monotonic() - started, 3)
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['status'].upper()}: {args.output / 'report.json'}")
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
