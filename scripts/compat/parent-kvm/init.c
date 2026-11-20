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
    int fixture = open("/ram-pages", O_RDONLY | O_CLOEXEC);
    check(fixture >= 0, "open fixture configuration");
    char pages[8];
    ssize_t page_bytes = read(fixture, pages, sizeof(pages));
    check(page_bytes > 0 && page_bytes < (ssize_t)sizeof(pages), "read fixture page count");
    pages[page_bytes] = '\0';
    close(fixture);
    pid_t child = fork();
    check(child >= 0, "fork the KVM client");
    if (child == 0) {
        char *arguments[16] = {"kvm-run", pages};
        unsigned int next = 2;
        if (access("/split-slot", F_OK) == 0)
            arguments[next++] = "split";
        else if (access("/protected-entry", F_OK) == 0)
            arguments[next++] = "protected";
        if (access("/interrupt-run", F_OK) == 0)
            arguments[next++] = "interrupt";
        if (access("/two-vcpus", F_OK) == 0)
            arguments[next++] = "smp";
        if (access("/long-mode", F_OK) == 0)
            arguments[next++] = "long";
        if (access("/floating-point", F_OK) == 0)
            arguments[next++] = "fpu";
        if (access("/boot-msrs", F_OK) == 0)
            arguments[next++] = "msrs";
        if (access("/cpuid-profile", F_OK) == 0)
            arguments[next++] = "cpuid";
        if (access("/mmio-write", F_OK) == 0)
            arguments[next++] = "mmio";
        if (access("/mmio-read", F_OK) == 0)
            arguments[next++] = "mmio-read";
        if (access("/ioeventfd", F_OK) == 0)
            arguments[next++] = "ioeventfd";
        if (access("/irqchip", F_OK) == 0)
            arguments[next++] = "irqchip";
        if (access("/pit", F_OK) == 0)
            arguments[next++] = "pit";
        if (access("/irqfd", F_OK) == 0)
            arguments[next++] = "irqfd";
        execv("/kvm-run", arguments);
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
