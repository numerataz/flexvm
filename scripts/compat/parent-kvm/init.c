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

#include "firecracker-net.h"
#include <linux/if_tun.h>
#if defined(FLEXVM_PARENT_KVM_APP) && defined(__x86_64__)
#include <linux/kvm.h>
#endif

static void fail_message(const char *why, const char *detail)
{
    fprintf(stderr, "FAIL parent KVM setup: %s: %s\n", why, detail);
    fflush(NULL);
#ifndef FLEXVM_PARENT_KVM_APP
    reboot(RB_POWER_OFF);
#endif
    _exit(1);
}

static void check(bool valid, const char *why)
{
    if (valid) return;
    fail_message(why, strerror(errno));
}

static void wait_child(pid_t child, const char *why)
{
    int status;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    check(waited == child, why);
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0)
            return;
        char detail[64];
        snprintf(detail, sizeof(detail), "exited with status %d", WEXITSTATUS(status));
        fail_message(why, detail);
    }
    if (WIFSIGNALED(status)) {
        char detail[64];
        snprintf(detail, sizeof(detail), "terminated by signal %d", WTERMSIG(status));
        fail_message(why, detail);
    }
    char detail[64];
    snprintf(detail, sizeof(detail), "unexpected wait status %#x", (unsigned int)status);
    fail_message(why, detail);
}

static void persist_tap(bool enabled)
{
    int tap = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    struct ifreq request = {.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", FLEXVM_TEST_TAP);
    check(tap >= 0 && ioctl(tap, TUNSETIFF, &request) == 0, "open Firecracker TAP");
    check(ioctl(tap, TUNSETPERSIST, enabled) == 0, "set Firecracker TAP persistence");
    close(tap);
}

static void serve_guest_network(int fd)
{
    struct sockaddr_in guest;
    socklen_t guest_size = sizeof(guest);
    char data[sizeof(FLEXVM_TEST_PACKET)];

    if (recvfrom(fd, data, sizeof(data), 0, (struct sockaddr *)&guest, &guest_size) != sizeof(data) ||
        memcmp(data, FLEXVM_TEST_PACKET, sizeof(data)) ||
        sendto(fd, data, sizeof(data), 0, (struct sockaddr *)&guest, guest_size) != sizeof(data)) {
        perror("Firecracker network echo");
        _exit(1);
    }
    _exit(0);
}

static void run_firecracker(void)
{
    pid_t echo = 0;
    if (access("/firecracker-network", F_OK) == 0) {
        persist_tap(true);
        int fd = test_datagram_socket(60);
        struct sockaddr_in local = test_network_peer();
        check(fd >= 0 && configure_test_link(fd, FLEXVM_TEST_TAP, FLEXVM_TEST_HOST) == 0 &&
              bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0, "configure Firecracker UDP peer");
        echo = fork();
        check(echo >= 0, "fork Firecracker network echo");
        if (echo == 0)
            serve_guest_network(fd);
        close(fd);
    }
    pid_t child = fork();
    check(child >= 0, "fork Firecracker");
    if (child == 0) {
        execl("/firecracker", "firecracker", "--no-api", "--config-file", "/firecracker.json", NULL);
        _exit(127);
    }
    wait_child(child, "Firecracker exit");
    if (echo > 0) {
        wait_child(echo, "Firecracker network echo exit");
        persist_tap(false);
        puts("PASS Firecracker network echo");
    }
}

#ifdef FLEXVM_PARENT_KVM_APP
#ifdef __x86_64__
static void checkpoint_initial_worker(void)
{
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0, "open parent KVM for initial-state checkpoint");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0 && ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create initial nested VM and interrupt controller");
    int cpu0 = ioctl(vm, KVM_CREATE_VCPU, 0);
    int cpu1 = ioctl(vm, KVM_CREATE_VCPU, 1);
    check(cpu0 >= 0 && cpu1 >= 0, "open two nested vCPUs before running");
    struct kvm_debugregs debug;
    check(ioctl(cpu0, KVM_GET_DEBUGREGS, &debug) == 0, "read reset debug registers");
    debug.db[0] = 0x1357000;
    check(ioctl(cpu0, KVM_SET_DEBUGREGS, &debug) == 0, "stage a debug register");
    struct kvm_mp_state mp = {.mp_state = KVM_MP_STATE_HALTED};
    check(ioctl(cpu0, KVM_SET_MP_STATE, &mp) == 0, "stage nested MP state");
    struct kvm_clock_data clock = {.clock = 1000000000000ULL};
    check(ioctl(vm, KVM_SET_CLOCK, &clock) == 0, "stage the nested VM clock");

    puts("FLEXVM_X86_PARENT_INITIAL");
    fflush(stdout);
    sleep(6);

    memset(&debug, 0, sizeof(debug));
    check(ioctl(cpu0, KVM_GET_DEBUGREGS, &debug) == 0 && debug.db[0] == 0x1357000,
          "restore the staged debug register");
    check(ioctl(cpu0, KVM_GET_MP_STATE, &mp) == 0 && mp.mp_state == KVM_MP_STATE_HALTED,
          "restore the staged MP state");
    check(ioctl(cpu1, KVM_GET_MP_STATE, &mp) == 0 && mp.mp_state == KVM_MP_STATE_UNINITIALIZED,
          "restore the second vCPU's uninitialized MP state");
    check(ioctl(vm, KVM_GET_CLOCK, &clock) == 0 && clock.clock >= 1000000000000ULL,
          "restore the staged VM clock");
    close(cpu1);
    close(cpu0);
    close(vm);
    close(kvm);
    puts("PASS x86 parent KVM staged worker state");
}
#endif
#else
static void run_kvm_client(void)
{
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
        if (access("/parent-memory-quota", F_OK) == 0)
            check(setenv("FLEXVM_TEST_PARENT_MEMORY_QUOTA", "1", 1) == 0, "set memory quota fixture");
        char *arguments[31] = {"kvm-run", pages};
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
        if (access("/zero-slot", F_OK) == 0)
            arguments[next++] = "zero-slot";
        if (access("/tss", F_OK) == 0)
            arguments[next++] = "provider-tss";
        if (access("/lapic", F_OK) == 0)
            arguments[next++] = "lapic";
        if (access("/pio", F_OK) == 0)
            arguments[next++] = "pio";
        if (access("/complete-read", F_OK) == 0)
            arguments[next++] = "complete-read";
        if (access("/pio-boundary", F_OK) == 0)
            arguments[next++] = "pio-boundary";
        if (access("/pvh", F_OK) == 0)
            arguments[next++] = "pvh";
        if (access("/irqchip-state", F_OK) == 0)
            arguments[next++] = "irqchip-state";
        if (access("/pit-state", F_OK) == 0)
            arguments[next++] = "pit-state";
        if (access("/debugregs", F_OK) == 0)
            arguments[next++] = "debugregs";
        if (access("/mp-state", F_OK) == 0)
            arguments[next++] = "mp-state";
        if (access("/xcrs", F_OK) == 0)
            arguments[next++] = "xcrs";
        if (access("/xsave", F_OK) == 0)
            arguments[next++] = "xsave";
        if (access("/vcpu-events", F_OK) == 0)
            arguments[next++] = "vcpu-events";
        if (access("/clock", F_OK) == 0)
            arguments[next++] = "clock";
        execv("/kvm-run", arguments);
        _exit(127);
    }
    wait_child(child, "KVM client exit");
}
#endif

int main(void)
{
#ifdef FLEXVM_PARENT_KVM_APP
    check(access("/sys/module/flexvm_pvkvm", F_OK) == 0, "parent KVM module was loaded by the guest init");
    if (access("/firecracker-idle-checkpoint", F_OK) == 0) {
        puts("FLEXVM_X86_PARENT_IDLE");
        fflush(stdout);
        sleep(6);
    }
#ifdef __x86_64__
    if (access("/firecracker-initial-checkpoint", F_OK) == 0)
        checkpoint_initial_worker();
#endif
    run_firecracker();
    run_firecracker();
    puts("PASS parent KVM device reuse");
#else
    check(mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) == 0, "mount devtmpfs");
    check(access("/dev/kvm", F_OK) == -1 && errno == ENOENT, "exclusive /dev/kvm provider");
    int module = open("/flexvm-pvkvm.ko", O_RDONLY | O_CLOEXEC);
    check(module >= 0, "open module");
    check(syscall(SYS_finit_module, module, "", 0) == 0, "load provider");
    close(module);
    if (access("/firecracker", X_OK) == 0) {
        check(mount("proc", "/proc", "proc", 0, NULL) == 0, "mount proc for Firecracker");
        check(mount("sysfs", "/sys", "sysfs", 0, NULL) == 0, "mount sysfs for Firecracker");
        run_firecracker();
    } else {
        run_kvm_client();
    }
    puts("PASS parent KVM guest shutdown");
    fflush(NULL);
    reboot(RB_POWER_OFF);
#endif
    return 0;
}
