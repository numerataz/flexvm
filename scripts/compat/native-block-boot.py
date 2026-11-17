#!/usr/bin/env python3
"""Native virtio-block cold-boot oracle; not a managed-volume implementation."""
import argparse
import ctypes
import fcntl
import http.client
import json
import os
from pathlib import Path
import platform
import re
import runpy
import signal
import socket
import subprocess
import tempfile
import time
import uuid

HELPERS = runpy.run_path(str(Path(__file__).with_name('software-boot.py')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firecracker', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--serial', help='require this explicitly configured guest-visible serial')
    args = parser.parse_args()
    args.firecracker = args.firecracker.resolve(strict=True)
    args.kernel = args.kernel.resolve(strict=True)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True)
    report = {'schema_version': 1, 'status': 'failed', 'arch': platform.machine(),
              'scope': 'native kernel virtio-block cold boot and flushed backing-file writes',
              'managed_volumes': False, 'snapshot_restore': False,
              'kernel_sha256': HELPERS['digest'](args.kernel),
              'firecracker_sha256': HELPERS['digest'](args.firecracker)}
    started = time.monotonic()
    nonce = uuid.uuid4().hex
    seed = f'SEED {nonce}'.encode()
    marker = f'FLEXVM_DISK_BOOT_OK {nonce}'.encode()
    source = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>
static const char seed[] = @SEED@;
static const char marker[] = @MARKER@;
static const char expected_serial[] = @SERIAL@;
int main(void) {
    if (getpid() != 1) return 2;
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755")) goto fail;
    int fd = -1;
    for (int i = 0; i < 100 && fd < 0; i++) {
        fd = open("/dev/vda", O_RDWR);
        if (fd < 0) usleep(20000);
    }
    if (fd < 0) goto fail;
    if (expected_serial[0]) {
        if (mkdir("/sys", 0755) && errno != EEXIST) goto fail;
        if (mount("sysfs", "/sys", "sysfs", MS_NOSUID, 0)) goto fail;
        int serial_fd = open("/sys/block/vda/serial", O_RDONLY);
        char seen[64] = {0};
        if (serial_fd < 0 || read(serial_fd, seen, sizeof(seen) - 1) <= 0) goto fail;
        close(serial_fd);
        seen[strcspn(seen, "\n")] = 0;
        if (strcmp(seen, expected_serial)) goto fail;
        printf("SERIAL_OK %s\n", seen);
    }
    char before[sizeof(seed)] = {0};
    if (pread(fd, before, sizeof(seed) - 1, 0) != sizeof(seed) - 1 || strcmp(before, seed)) goto fail;
    if (pwrite(fd, marker, sizeof(marker) - 1, 4096) != sizeof(marker) - 1 || fsync(fd)) goto fail;
    close(fd);
    puts(marker);
    fflush(stdout);
    sync();
    reboot(RB_POWER_OFF);
fail:
    perror("native-block-boot");
    for (;;) pause();
}
'''
    for token, value in {'@SEED@': seed.decode(), '@MARKER@': marker.decode(), '@SERIAL@': args.serial or ''}.items():
        source = source.replace(token, json.dumps(value))
    process = None
    try:
        with open('/dev/kvm', 'r+b', buffering=0) as kvm:
            if fcntl.ioctl(kvm, 0xAE00, 0) != 12:
                raise RuntimeError('unsupported native KVM API')
        cfile = args.output / 'init.c'
        binary = args.output / 'init'
        cfile.write_text(source)
        with (args.output / 'compile.log').open('w') as log:
            subprocess.run(['cc', '-static', '-Os', '-Wall', '-Wextra', '-Werror', str(cfile), '-o', str(binary)],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
        disk_path = args.output / 'disk.raw'
        with disk_path.open('x+b') as disk, tempfile.TemporaryDirectory(prefix='fvblk-') as temporary:
            disk.truncate(16 << 20)
            disk.write(seed)
            disk.flush()
            os.fsync(disk.fileno())
            fcntl.flock(disk, fcntl.LOCK_EX | fcntl.LOCK_NB)
            temporary = Path(temporary)
            archive = temporary / 'init.cpio'
            archive.write_bytes(HELPERS['initramfs'](binary.read_bytes()))
            api = temporary / 'api.sock'
            deadline = time.monotonic() + 30
            console = args.output / 'console.log'
            with console.open('w') as output:
                parent = os.getpid()
                libc = ctypes.CDLL(None, use_errno=True)

                def guard():
                    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
                        os._exit(127)

                process = subprocess.Popen(['strace', '--kill-on-exit', '-ff', '-yy', '-e', 'trace=fsync,fdatasync,pwrite64',
                                            '-o', str(args.output / 'io.strace'), str(args.firecracker), '--api-sock', str(api)], stdin=subprocess.DEVNULL,
                                           stdout=output, stderr=subprocess.STDOUT, pass_fds=(disk.fileno(),), preexec_fn=guard, cwd=args.output)
                while not api.exists():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('native VMM did not publish its API socket')
                    time.sleep(.01)

                def put(path, value):
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise TimeoutError('native block boot deadline')
                    connection = http.client.HTTPConnection('localhost', timeout=left)
                    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    stream.settimeout(left)
                    try:
                        stream.connect(str(api))
                        connection.sock = stream
                        connection.request('PUT', path, json.dumps(value), {'Content-Type': 'application/json'})
                        response = connection.getresponse()
                        data = response.read()
                        if response.status != 204:
                            raise RuntimeError(f'{path}: HTTP {response.status}: {data!r}')
                    finally:
                        connection.close()
                        stream.close()

                tty = 'ttyS0' if platform.machine() == 'x86_64' else 'ttyAMA0'
                put('/boot-source', {'kernel_image_path': str(args.kernel), 'initrd_path': str(archive),
                                     'boot_args': f'console={tty} quiet panic=1 rdinit=/init'})
                put('/machine-config', {'vcpu_count': 1, 'mem_size_mib': 256})
                drive = {'drive_id': 'data', 'path_on_host': 'disk.raw',
                         'is_root_device': False, 'is_read_only': False, 'io_engine': 'Sync', 'cache_type': 'Writeback'}
                if args.serial is not None:
                    drive['serial'] = args.serial
                put('/drives/data', drive)
                put('/actions', {'action_type': 'InstanceStart'})
                code = process.wait(timeout=max(.1, deadline - time.monotonic()))
            disk.seek(4096)
            observed = disk.read(len(marker))
            log = console.read_text(errors='replace')
            if code != 0 or observed != marker or marker.decode() not in log or 'Kernel panic' in log:
                raise RuntimeError(f'block guest did not flush and power off: status={code}, marker={observed!r}')
            if args.serial is not None and f'SERIAL_OK {args.serial}' not in log:
                raise RuntimeError('guest did not confirm the configured serial')
            flush = re.compile(r'(?:fsync|fdatasync)\(\d+<' + re.escape(str(disk_path)) + r'>\)\s*= 0')
            if not any(flush.search(path.read_text(errors='replace')) for path in args.output.glob('io.strace.*')):
                raise RuntimeError('guest fsync did not produce a successful host backing-file flush')
            report.update(status='passed', owner_status=code, flushed_marker=observed.decode(), serial=args.serial,
                          host_backing_flush=True, cache_type='Writeback',
                          disk_bytes=disk_path.stat().st_size, disk_sha256=HELPERS['digest'](disk_path),
                          init_sha256=HELPERS['digest'](binary))
    except Exception as error:
        report['error'] = str(error)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        report['elapsed_s'] = round(time.monotonic() - started, 3)
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['status'].upper()}: {args.output / 'report.json'}")
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
