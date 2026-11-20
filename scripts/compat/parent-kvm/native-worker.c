#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kvm.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
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

static int host_kvm(void)
{
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION,
          "open a compatible host KVM device");
    return kvm;
}

static void supported_cpuid(void)
{
    struct pvkvm_cpuid_table table = {.count = PVKVM_CPUID_MAX};
    int kvm = host_kvm();
    check(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, &table) == 0 && table.count <= PVKVM_CPUID_MAX,
          "read the host supported CPUID table");
    size_t bytes = offsetof(struct pvkvm_cpuid_table, entries) + table.count * sizeof(table.entries[0]);
    check(write(STDOUT_FILENO, &table, bytes) == (ssize_t)bytes, "write the supported CPUID table");
    close(kvm);
}

static void reset_lapic(unsigned int id)
{
    struct kvm_lapic_state lapic;
    int kvm = host_kvm();
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0 && ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create a host IRQ controller");
    int cpu = ioctl(vm, KVM_CREATE_VCPU, id);
    check(cpu >= 0 && ioctl(cpu, KVM_GET_LAPIC, &lapic) == 0, "read the host reset LAPIC");
    check(write(STDOUT_FILENO, &lapic, sizeof(lapic)) == sizeof(lapic), "write the reset LAPIC image");
    close(cpu);
    close(vm);
    close(kvm);
}

struct pending_read {
    unsigned char *data;
    size_t length;
};

static struct pending_read reply_run(int control, struct kvm_run *run, int mapping_bytes)
{
    if (run->exit_reason == KVM_EXIT_MMIO) {
        unsigned int width = run->mmio.len;
        check(width == 1 || width == 2 || width == 4 || width == 8,
              "unexpected host MMIO access");
        unsigned char output[18] = {run->mmio.is_write ? 'M' : 'Q', width};
        memcpy(output + 2, &run->mmio.phys_addr, sizeof(run->mmio.phys_addr));
        if (run->mmio.is_write)
            memcpy(output + 10, run->mmio.data, width);
        check(write(control, output, sizeof(output)) == sizeof(output), "return a host MMIO exit");
        return run->mmio.is_write ? (struct pending_read){0} : (struct pending_read){run->mmio.data, width};
    }
    check(run->exit_reason == KVM_EXIT_IO && run->io.direction <= KVM_EXIT_IO_OUT &&
          (run->io.size == 1 || run->io.size == 2 || run->io.size == 4) &&
          run->io.count > 0 && run->io.count <= PVKVM_PIO_BYTES / run->io.size &&
          run->io.data_offset < (unsigned long)mapping_bytes, "invalid host port I/O exit");
    size_t length = (size_t)run->io.count * run->io.size;
    check(length <= (unsigned long)mapping_bytes - run->io.data_offset, "host I/O data outside run mapping");
    unsigned char *data = (unsigned char *)run + run->io.data_offset;
    bool is_write = run->io.direction == KVM_EXIT_IO_OUT;
    unsigned char output[8 + PVKVM_PIO_BYTES] = {is_write ? 'U' : 'V', run->io.size};
    memcpy(output + 2, &run->io.port, sizeof(run->io.port));
    memcpy(output + 4, &run->io.count, sizeof(run->io.count));
    if (is_write)
        memcpy(output + 8, data, length);
    size_t bytes = 8 + (is_write ? length : 0);
    check(write(control, output, bytes) == (ssize_t)bytes, "return a host port I/O exit");
    return is_write ? (struct pending_read){0} : (struct pending_read){data, length};
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--supported-cpuid")) {
        supported_cpuid();
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--reset-lapic")) {
        reset_lapic(number(argv[2], PVKVM_MAX_CPUS - 1));
        return 0;
    }
    check(argc >= 10, "expected control, outer RAM, vCPU count, device configuration, and slots");
    int control = (int)number(argv[1], INT_MAX);
    int outer_ram = (int)number(argv[2], INT_MAX);
    unsigned int cpu_count = number(argv[3], PVKVM_MAX_CPUS);
    bool irqchip = number(argv[4], 1);
    unsigned int pit_request = number(argv[5], KVM_PIT_SPEAKER_DUMMY + 1);
    unsigned long tss = number(argv[6], UINT32_MAX);
    int first_slot = 7 + (irqchip ? PVKVM_GSI_COUNT : 0);
    check(argc >= first_slot + 3 && (argc - first_slot) % 3 == 0 &&
          (argc - first_slot) / 3 <= PVKVM_MAX_SLOTS, "invalid worker RAM slots or interrupt descriptors");
    check(cpu_count > 0, "at least one native vCPU");

    int kvm = host_kvm();
    int bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    check(bytes >= (int)sizeof(struct kvm_run), "KVM run mapping size");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0, "create host VM");
    if (tss != UINT32_MAX)
        check(ioctl(vm, KVM_SET_TSS_ADDR, tss) == 0, "reserve the host VM TSS address");
    if (irqchip) {
        check(ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create the host irqchip");
        for (unsigned int gsi = 0; gsi < PVKVM_GSI_COUNT; gsi++) {
            struct kvm_irqfd irq = {.fd = number(argv[7 + gsi], INT_MAX), .gsi = gsi};
            check(ioctl(vm, KVM_IRQFD, &irq) == 0, "connect a host irqfd doorbell");
        }
    }
    if (pit_request) {
        struct kvm_pit_config pit = {.flags = pit_request - 1};
        check(ioctl(vm, KVM_CREATE_PIT2, &pit) == 0, "create the host PIT");
    }
    for (int arg = first_slot; arg < argc; arg += 3) {
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
    struct pending_read pending_read[PVKVM_MAX_CPUS] = {0};
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
    struct kvm_fpu fpu;
    struct kvm_lapic_state lapic;
    struct pvkvm_msr_batch msrs;
    struct pvkvm_cpuid_table cpuid;
    _Static_assert(sizeof(fpu) == PVKVM_FPU_BYTES && sizeof(cpuid) >= sizeof(fpu) &&
                   sizeof(lapic) == PVKVM_LAPIC_BYTES && sizeof(cpuid) >= sizeof(lapic) &&
                   sizeof(cpuid) >= PVKVM_PIO_BYTES + sizeof(uint32_t) &&
                   sizeof(cpuid) >= sizeof(segments) && sizeof(cpuid) >= sizeof(msrs),
                   "native worker control record size");

    check(write(control, "R", 1) == 1, "announce worker readiness");
    unsigned char request[2 + sizeof(cpuid)];
    ssize_t received;
    while ((received = recv(control, request, sizeof(request), MSG_TRUNC)) != 0) {
        if (received < 0 && errno == EINTR) continue;
        check(received >= 2 && request[1] < cpu_count, "invalid vCPU selector");
        unsigned int id = request[1];
        int cpu = cpus[id];
        struct kvm_run *run = runs[id];
        if (received == 2 + sizeof(registers) && request[0] == 'S') {
            memcpy(&registers, request + 2, sizeof(registers));
            check(ioctl(cpu, KVM_SET_REGS, &registers) == 0, "write host registers");
            check(write(control, "S", 1) == 1, "acknowledge host register write");
            continue;
        }
        if (received == 2 + sizeof(segments) && request[0] == 'P') {
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
            segments.cr3 = setup.cr3;
            segments.cr4 |= setup.cr4;
            segments.efer |= setup.efer;
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
        if (received == 2 + sizeof(struct kvm_irq_level) && request[0] == 'L') {
            struct kvm_irq_level irq;
            memcpy(&irq, request + 2, sizeof(irq));
            check(irqchip && irq.irq < PVKVM_GSI_COUNT && irq.level <= 1 &&
                  ioctl(vm, KVM_IRQ_LINE, &irq) == 0, "set a host IRQ line");
            check(write(control, "L", 1) == 1, "acknowledge host IRQ line state");
            continue;
        }
        if (received == 2 && request[0] == 'F') {
            check(ioctl(cpu, KVM_GET_FPU, &fpu) == 0, "read host floating-point registers");
            check(write(control, &fpu, sizeof(fpu)) == (ssize_t)sizeof(fpu), "return host floating-point state");
            continue;
        }
        if (received == 2 + sizeof(fpu) && request[0] == 'W') {
            memcpy(&fpu, request + 2, sizeof(fpu));
            check(ioctl(cpu, KVM_SET_FPU, &fpu) == 0, "write host floating-point registers");
            check(write(control, "W", 1) == 1, "acknowledge host floating-point write");
            continue;
        }
        if (received == 2 && request[0] == 'A') {
            check(ioctl(cpu, KVM_GET_LAPIC, &lapic) == 0, "read host LAPIC");
            check(write(control, &lapic, sizeof(lapic)) == sizeof(lapic), "return host LAPIC state");
            continue;
        }
        if (received == 2 + sizeof(lapic) && request[0] == 'B') {
            memcpy(&lapic, request + 2, sizeof(lapic));
            check(ioctl(cpu, KVM_SET_LAPIC, &lapic) == 0, "write host LAPIC");
            check(write(control, "B", 1) == 1, "acknowledge host LAPIC state");
            continue;
        }
        if (request[0] == 'M' || request[0] == 'N') {
            const size_t header = offsetof(struct pvkvm_msr_batch, entries);
            bool set = request[0] == 'N';
            check(received >= 2 + (ssize_t)header && received <= 2 + (ssize_t)sizeof(msrs),
                  "invalid host MSR request size");
            size_t payload = received - 2;
            memcpy(&msrs, request + 2, payload);
            check(msrs.count <= PVKVM_MSR_BATCH_MAX &&
                  payload == header + msrs.count * sizeof(msrs.entries[0]), "invalid host MSR batch");
            int processed = ioctl(cpu, set ? KVM_SET_MSRS : KVM_GET_MSRS, &msrs);
            check(processed >= 0 && (uint32_t)processed <= msrs.count, "access host MSR registers");
            msrs.count = processed;
            size_t response = header + (set ? 0 : msrs.count * sizeof(msrs.entries[0]));
            check(write(control, &msrs, response) == (ssize_t)response, "return host MSR batch result");
            continue;
        }
        if (request[0] == 'C') {
            const size_t header = offsetof(struct pvkvm_cpuid_table, entries);
            check(received >= 2 + (ssize_t)header && received <= (ssize_t)sizeof(request),
                  "invalid host CPUID request size");
            size_t payload = received - 2;
            memcpy(&cpuid, request + 2, payload);
            check(cpuid.count <= PVKVM_CPUID_MAX &&
                  payload == header + cpuid.count * sizeof(cpuid.entries[0]), "invalid host CPUID table");
            check(ioctl(cpu, KVM_SET_CPUID2, &cpuid) == 0, "configure host CPUID table");
            check(write(control, "C", 1) == 1, "acknowledge host CPUID table");
            continue;
        }
        uint32_t sequence;
        size_t run_header = 2 + sizeof(sequence);
        check(received == (ssize_t)(run_header + pending_read[id].length) && request[0] == 'R', "invalid run request");
        memcpy(&sequence, request + 2, sizeof(sequence));
        check(sequence > 0 && sequence <= INT_MAX, "invalid run sequence");
        if (pending_read[id].length) {
            memcpy(pending_read[id].data, request + run_header, pending_read[id].length);
            pending_read[id] = (struct pending_read){0};
        }
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
        pending_read[id] = reply_run(control, run, bytes);
    }
    return 0;
}
