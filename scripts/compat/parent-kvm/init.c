#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void check(bool valid, const char *why)
{
    if (valid) return;
    fprintf(stderr, "FAIL parent KVM setup: %s: %s\n", why, strerror(errno));
    fflush(NULL);
    reboot(RB_POWER_OFF);
    _exit(1);
}

int main(void)
{
    check(mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) == 0, "mount devtmpfs");
    check(access("/dev/kvm", F_OK) == -1 && errno == ENOENT, "exclusive /dev/kvm provider");
    int module = open("/flexvm-pvkvm.ko", O_RDONLY | O_CLOEXEC);
    check(module >= 0, "open module");
    check(syscall(SYS_finit_module, module, "", 0) == 0, "load provider");
    close(module);
    check(chmod("/kvm-run", 0700) == 0, "make the client executable");
    const char *pages = access("/single-page", F_OK) == 0 ? "1" : "2";
    pid_t child = fork();
    check(child >= 0, "fork the KVM client");
    if (child == 0) {
        execl("/kvm-run", "kvm-run", pages, NULL);
        _exit(127);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "KVM client exit");
    puts("PASS parent KVM guest shutdown");
    fflush(NULL);
    reboot(RB_POWER_OFF);
    return 0;
}
