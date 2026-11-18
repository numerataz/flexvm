/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void check(int ok, const char *why)
{
    if (ok) return;
    perror(why);
    reboot(RB_POWER_OFF);
    _exit(1);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    check(mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) == 0, "mount devtmpfs");
    check(mount("proc", "/proc", "proc", 0, NULL) == 0, "mount proc");
    check(mount("sysfs", "/sys", "sysfs", 0, NULL) == 0, "mount sysfs");
    check(access("/dev/kvm", F_OK) == -1 && errno == ENOENT, "exclusive provider");
    int module = open("/flexvm-pvkvm.ko", O_RDONLY | O_CLOEXEC);
    check(module >= 0 && syscall(SYS_finit_module, module, "", 0) == 0, "load ARM provider");
    close(module);
    pid_t child = fork();
    check(child >= 0, "fork ARM Firecracker");
    if (!child) {
        execl("/firecracker", "firecracker", "--no-api", "--config-file", "/firecracker.json", NULL);
        _exit(127);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "ARM Firecracker exit");
    int fd = open("/tmp/drive", O_RDONLY | O_CLOEXEC);
    const char written[] = "ARM inner completed block write";
    char data[sizeof(written)];
    check(fd >= 0 && pread(fd, data, sizeof(data), 4096) == sizeof(data) &&
          memcmp(data, written, sizeof(written)) == 0, "outer Firecracker drive received nested writes");
    close(fd);
    puts("PASS stock ARM Firecracker used the parent-owned KVM device");
    reboot(RB_POWER_OFF);
    return 0;
}
