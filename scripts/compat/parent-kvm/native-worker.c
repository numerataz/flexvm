#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kvm.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include "mailbox.h"
#include "slot-map.h"

static struct kvm_run *run_page;
static volatile sig_atomic_t active_run;
static volatile sig_atomic_t cancelled_run;

static void interrupt_run(int signal, siginfo_t *info, void *context)
{
    (void)signal;
    (void)context;
    if (info->si_code != SI_QUEUE || info->si_value.sival_int <= 0)
        return;
    cancelled_run = info->si_value.sival_int;
    if (cancelled_run == active_run)
        __atomic_store_n(&run_page->immediate_exit, 1, __ATOMIC_RELAXED);
}

static void check(bool condition, const char *why)
{
    if (condition) return;
    fprintf(stderr, "native parent worker: %s (%s)\n", why, strerror(errno));
    exit(1);
}

static unsigned long number(const char *text, unsigned long maximum)
{
    char *end;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    check(text[0] >= '0' && text[0] <= '9' && !errno && !*end && value <= maximum,
          "invalid worker argument");
    return value;
}

int main(int argc, char **argv)
{
    check(argc >= 7 && (argc - 4) % 3 == 0 &&
          (argc - 4) / 3 <= PVKVM_MAX_SLOTS, "expected control, outer RAM, vCPU count, and slot triples");
    int control = (int)number(argv[1], INT_MAX);
    int outer_ram = (int)number(argv[2], INT_MAX);
    unsigned int cpu_count = number(argv[3], PVKVM_MAX_CPUS);
    check(cpu_count > 0, "at least one native vCPU");

    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION,
          "open a compatible host KVM device");
    int bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    check(bytes >= (int)sizeof(struct kvm_run), "KVM run mapping size");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0, "create host VM");
    for (int arg = 4; arg < argc; arg += 3) {
        int layout = (int)number(argv[arg], INT_MAX);
        uint64_t gpa = number(argv[arg + 1], UINT32_MAX);
        uint32_t id = number(argv[arg + 2], PVKVM_MAX_SLOTS - 1);
        size_t slot_bytes;
        void *slot = flexvm_map_slot(outer_ram, layout, &slot_bytes);
        check(slot != MAP_FAILED, "map a parent RAM slot");
        close(layout);
        struct kvm_userspace_memory_region memory = {
            .slot = id, .guest_phys_addr = gpa, .memory_size = slot_bytes,
            .userspace_addr = (uintptr_t)slot,
        };
        check(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &memory) == 0, "register a shared RAM slot");
    }
    close(outer_ram);
    int cpus[PVKVM_MAX_CPUS];
    struct kvm_run *runs[PVKVM_MAX_CPUS];
    struct kvm_sregs segments;
    for (unsigned int id = 0; id < cpu_count; id++) {
        cpus[id] = ioctl(vm, KVM_CREATE_VCPU, id);
        check(cpus[id] >= 0, "create host vCPU");
        runs[id] = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, cpus[id], 0);
        check(runs[id] != MAP_FAILED, "map host kvm_run");
        check(ioctl(cpus[id], KVM_GET_SREGS, &segments) == 0, "read reset segments");
        segments.cs.base = 0;
        segments.cs.selector = 0;
        check(ioctl(cpus[id], KVM_SET_SREGS, &segments) == 0, "select real-mode code segment");
    }
    struct sigaction action = {.sa_sigaction = interrupt_run, .sa_flags = SA_SIGINFO | SA_RESTART};
    check(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGRTMIN, &action, NULL) == 0,
          "install the native run interrupt handler");
    struct kvm_regs registers;

    check(write(control, "R", 1) == 1, "announce worker readiness");
    unsigned char request[2 + sizeof(segments)];
    ssize_t received;
    while ((received = recv(control, request, sizeof(request), MSG_TRUNC)) != 0) {
        if (received < 0 && errno == EINTR) continue;
        check(received >= 2 && request[1] < cpu_count, "invalid vCPU selector");
        int cpu = cpus[request[1]];
        struct kvm_run *run = runs[request[1]];
        if (received == 2 + sizeof(registers) && request[0] == 'S') {
            memcpy(&registers, request + 2, sizeof(registers));
            check(ioctl(cpu, KVM_SET_REGS, &registers) == 0, "write host registers");
            check(write(control, "S", 1) == 1, "acknowledge host register write");
            continue;
        }
        if (received == sizeof(request) && request[0] == 'P') {
            struct kvm_sregs setup;
            memcpy(&setup, request + 2, sizeof(setup));
            check(ioctl(cpu, KVM_GET_SREGS, &segments) == 0, "read host protected-entry baseline");
            segments.cs = setup.cs;
            segments.ds = setup.ds;
            segments.es = setup.es;
            segments.fs = setup.fs;
            segments.gs = setup.gs;
            segments.ss = setup.ss;
            segments.gdt = setup.gdt;
            segments.cr0 |= setup.cr0;
            check(ioctl(cpu, KVM_SET_SREGS, &segments) == 0, "configure host protected mode");
            check(write(control, "P", 1) == 1, "acknowledge host protected mode");
            continue;
        }
        if (received == 2 && request[0] == 'G') {
            check(ioctl(cpu, KVM_GET_REGS, &registers) == 0, "read host registers after exit");
            check(write(control, &registers, sizeof(registers)) == (ssize_t)sizeof(registers),
                  "return host registers to the parent");
            continue;
        }
        if (received == 2 && request[0] == 'X') {
            check(ioctl(cpu, KVM_GET_SREGS, &segments) == 0, "read host special registers after exit");
            check(write(control, &segments, sizeof(segments)) == (ssize_t)sizeof(segments),
                  "return host special registers to the parent");
            continue;
        }
        uint32_t sequence;
        check(received == 2 + sizeof(sequence) && request[0] == 'R', "invalid run request");
        memcpy(&sequence, request + 2, sizeof(sequence));
        check(sequence > 0 && sequence <= INT_MAX, "invalid run sequence");
        run_page = run;
        __atomic_store_n(&run->immediate_exit, 0, __ATOMIC_RELAXED);
        /* The signal handler may publish an interrupt as soon as this
         * sequence becomes active. Finish clearing the old value first.
         */
        __atomic_signal_fence(__ATOMIC_SEQ_CST);
        active_run = (sig_atomic_t)sequence;
        if (cancelled_run == active_run)
            __atomic_store_n(&run->immediate_exit, 1, __ATOMIC_RELAXED);
        int result = ioctl(cpu, KVM_RUN, 0);
        active_run = 0;
        if (result < 0 && errno == EINTR && cancelled_run == (sig_atomic_t)sequence) {
            static const unsigned char interrupted[] = {'I', 0};
            check(write(control, interrupted, sizeof(interrupted)) == sizeof(interrupted),
                  "acknowledge the stopped host vCPU");
            continue;
        }
        check(result == 0, "run host vCPU");
        check(run->exit_reason == KVM_EXIT_IO && run->io.direction == KVM_EXIT_IO_OUT &&
              run->io.port == 0x30 && run->io.count == 1 && run->io.size == 1 &&
              run->io.data_offset < (unsigned long)bytes, "unexpected host vCPU exit");
        unsigned char output[] = {'O', ((unsigned char *)run)[run->io.data_offset]};
        check(write(control, output, sizeof(output)) == sizeof(output), "reply to the parent");
    }
    return 0;
}
