#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "mailbox.h"

#define PROTECTED_SLOT_GPA 0x1000000
#define SPLIT_SLOT_GPA 0x20000000
#define GDT_OFFSET 0x200
#define SECOND_CPU_OFFSET 0x300
#define FPU_ENTRY_OFFSET 0x400
#define FPU_RESUME_OFFSET 0x480
#define MSR_ENTRY_OFFSET 0x500
#define MSR_RESUME_OFFSET 0x600
#define CPUID_ENTRY_OFFSET 0x700
#define CPUID_SECOND_OFFSET 0x800
#define MMIO_ENTRY_OFFSET 0x900
#define MMIO_READ_OFFSET 0xa00
#define PIO_EVENTFD_OFFSET 0xb00
#define MMIO_DEASSIGNED_OFFSET 0xb80
#define MMIO_BASE 0xd0000000ULL
#define MMIO_FIRST_VALUE 0x5a443322U
#define MMIO_SECOND_VALUE 0xaabbccddeeff0011ULL
#define CPUID_TEST_FUNCTION 0x4000007e
#define CPUID_TEST_RESULT 0x31234500
#define TSC_START 0x1111222200000000ULL
#define MSR_KERNEL_GS_BASE 0xc0000102U
#define MSR_MTRR_DEFAULT 0x2ff
#define GS_BASE_INITIAL 0x07654321U
#define GS_BASE_FROM_GUEST 0x12345678U
#define GS_BASE_FOR_RESUME 0x2468ace0U
#define LONG_ALIAS 0x4001000000ULL
#define HUGE_PAGE_SIZE 0x200000ULL
#define LONG_REGISTER 0x8fedcba987654321ULL
#define LONG_CR0 0x80000001ULL
#define LONG_CR4 0x20ULL
#define LONG_EFER 0x500ULL
#define TEST_INTERRUPTS 3

static void check(bool valid, const char *why)
{
    if (valid) return;
    fprintf(stderr, "FAIL parent KVM: %s: %s\n", why, strerror(errno));
    exit(1);
}

static unsigned long long timed_run(int cpu)
{
    struct timespec start, end;
    check(clock_gettime(CLOCK_MONOTONIC_RAW, &start) == 0, "read start time");
    check(ioctl(cpu, KVM_RUN, 0) == 0, "execute vCPU");
    check(clock_gettime(CLOCK_MONOTONIC_RAW, &end) == 0, "read exit time");
    return (end.tv_sec - start.tv_sec) * 1000000000LL + end.tv_nsec - start.tv_nsec;
}

static void check_output(struct kvm_run *run, int bytes, unsigned char value)
{
    check(run->exit_reason == KVM_EXIT_IO && run->io.direction == KVM_EXIT_IO_OUT &&
          run->io.size == 1 && run->io.count == 1 && run->io.port == 0x30 &&
          run->io.data_offset < (unsigned)bytes &&
          ((unsigned char *)run)[run->io.data_offset] == value, "KVM I/O exit");
}

static struct kvm_regs check_registers(int cpu, unsigned char accumulator, unsigned int counter, uint64_t start)
{
    struct kvm_regs regs;

    check(ioctl(cpu, KVM_GET_REGS, &regs) == 0, "read actual registers after exit");
    check((regs.rax & 0xff) == accumulator && regs.rcx == counter &&
          regs.rip >= start && (regs.rflags & 2), "check actual registers after exit");
    return regs;
}

static void select_segments(int cpu, bool protected_mode, bool long_mode, uint64_t gpa)
{
    struct kvm_sregs sregs;
    check(ioctl(cpu, KVM_GET_SREGS, &sregs) == 0, "read reset segments");
    if (protected_mode) {
        const struct kvm_segment code = {
            .limit = UINT32_MAX, .selector = 8, .type = 11, .present = 1,
            .db = !long_mode, .s = 1, .l = long_mode, .g = 1,
        };
        const struct kvm_segment data = {
            .limit = UINT32_MAX, .selector = 16, .type = 3, .present = 1,
            .db = 1, .s = 1, .g = 1,
        };
        sregs.cs = code;
        sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = data;
        sregs.gdt = (struct kvm_dtable){.base = gpa + GDT_OFFSET, .limit = 23};
        sregs.cr0 |= 1;
        if (long_mode) {
            sregs.cr0 |= LONG_CR0;
            sregs.cr3 = gpa + 4096;
            sregs.cr4 |= LONG_CR4;
            sregs.efer |= LONG_EFER;
        }
    } else {
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
    }
    check(ioctl(cpu, KVM_SET_SREGS, &sregs) == 0, "select the child execution mode");
}

static void setup_page_tables(unsigned char *ram, uint64_t gpa, uint64_t middle, uint64_t last, bool mmio)
{
    uint64_t *level4 = (uint64_t *)(ram + 4096);
    uint64_t *level3 = (uint64_t *)(ram + 8192);
    uint64_t *level2 = (uint64_t *)(ram + 12288);
    const size_t entry = (LONG_ALIAS >> 21) & 511;

    level4[(LONG_ALIAS >> 39) & 511] = (gpa + 8192) | 3;
    level3[0] = (gpa + 12288) | 3; /* Keep the GDT identity mapped. */
    level3[(LONG_ALIAS >> 30) & 511] = (gpa + 12288) | 3;
    level2[entry] = gpa | 0x83;
    level2[entry + 1] = (middle & ~(HUGE_PAGE_SIZE - 1)) | 0x83;
    level2[entry + 2] = (last & ~(HUGE_PAGE_SIZE - 1)) | 0x83;
    if (mmio)
        level2[entry + 3] = MMIO_BASE | 0x83;
}

static void prepare_fpu(int cpu)
{
    const struct kvm_fpu fpu = {.fcw = 0x37f, .mxcsr = 0x1f80};
    struct kvm_fpu staged;

    check(ioctl(cpu, KVM_SET_FPU, &fpu) == 0, "stage x87 and XMM state before entry");
    check(ioctl(cpu, KVM_GET_FPU, &staged) == 0 &&
          staged.fcw == fpu.fcw && staged.fsw == fpu.fsw && staged.ftwx == fpu.ftwx && !staged.mxcsr &&
          !memcmp(staged.fpr[0], fpu.fpr[0], 10) &&
          !memcmp(staged.xmm[0], fpu.xmm[0], sizeof(fpu.xmm[0])),
          "read staged x87 and XMM state");
}

static void update_fpu(int cpu, const unsigned char *ram)
{
    struct kvm_fpu observed;
    uint16_t control;
    uint32_t integer;

    memcpy(&control, ram + 0xb0, sizeof(control));
    memcpy(&integer, ram + 0xb4, sizeof(integer));
    check(control == 0x77f && integer == 1, "child executed x87 instructions");
    check(ioctl(cpu, KVM_GET_FPU, &observed) == 0 && observed.fcw == 0x77f &&
          ((observed.fsw >> 11) & 7) == 7 && observed.ftwx == (1 << 7) &&
          observed.xmm[0][0] == 0xfe && observed.xmm[0][1] == 0xfe && observed.xmm[0][15] == 0xfe,
          "read x87 and XMM changes made by the child");
    const struct kvm_fpu fpu = {
        .fcw = 0xb7f, .fsw = 5 << 11, .ftwx = 1 << 5,
        .fpr = {{0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0x40}}, /* ST(0) = 2.0 */
        .xmm = {{7, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30}},
    };
    check(ioctl(cpu, KVM_SET_FPU, &fpu) == 0, "update floating-point state after the exit");
}

static void check_resumed_fpu(int cpu, const unsigned char *data)
{
    struct kvm_fpu fpu;
    uint16_t control;
    uint32_t integer;
    uint32_t mxcsr;

    memcpy(&control, data + 0xb0, sizeof(control));
    memcpy(&integer, data + 0xb4, sizeof(integer));
    memcpy(&mxcsr, data + 0xbc, sizeof(mxcsr));
    check(control == 0xb7f && integer == 2 && mxcsr == 0x3f80 &&
          ioctl(cpu, KVM_GET_FPU, &fpu) == 0 && fpu.fcw == 0xb7f &&
          ((fpu.fsw >> 11) & 7) == 6 && !fpu.ftwx &&
          fpu.xmm[0][0] == 14 && fpu.xmm[0][1] == 8 && fpu.xmm[0][15] == 60,
          "read updated floating-point state after re-entry");
    puts("PASS x87 and XMM state reached the parent worker");
}

static void install_jump(unsigned char *ram, int from, int to)
{
    int32_t target = to - (from + 5);
    ram[from] = 0xe9;
    memcpy(ram + from + 1, &target, sizeof(target));
}

static void prepare_msrs(int device, int cpu)
{
    const struct pvkvm_msr_batch initial = {
        .count = 11,
        .entries = {
            {.index = 0x174}, {.index = 0x175}, {.index = 0x176},
            {.index = 0xc0000081}, {.index = 0xc0000083},
            {.index = MSR_KERNEL_GS_BASE, .data = GS_BASE_INITIAL},
            {.index = 0xc0000084}, {.index = 0xc0000082},
            {.index = 0x10, .data = TSC_START},
            {.index = 0x1a0, .data = 1}, {.index = MSR_MTRR_DEFAULT, .data = 0x806},
        },
    };
    struct kvm_msr_list size = {0};

    check(ioctl(device, KVM_GET_MSR_INDEX_LIST, &size) == -1 && errno == E2BIG &&
          size.nmsrs >= initial.count && size.nmsrs <= 4096, "query the MSR index list capacity");
    struct kvm_msr_list *list = calloc(1, sizeof(*list) + size.nmsrs * sizeof(list->indices[0]));
    check(list != NULL, "allocate the MSR index list");
    list->nmsrs = size.nmsrs;
    check(ioctl(device, KVM_GET_MSR_INDEX_LIST, list) == 0 && list->nmsrs <= size.nmsrs,
          "query supported MSR indices");
    for (unsigned int i = 0; i < initial.count; i++) {
        /* KVM's save list need not include the separately writable MTRR default. */
        if (initial.entries[i].index == MSR_MTRR_DEFAULT)
            continue;
        bool found = false;
        for (unsigned int j = 0; j < list->nmsrs; j++) {
            if (list->indices[j] == initial.entries[i].index) {
                found = true;
                break;
            }
        }
        if (!found)
            fprintf(stderr, "Linux boot MSR %#x is absent from the index list\n", initial.entries[i].index);
        check(found, "find an MSR used to boot x86 Linux");
    }
    free(list);
    check(ioctl(cpu, KVM_SET_MSRS, &initial) == (int)initial.count, "set the x86 Linux boot MSR batch");
    struct pvkvm_msr_batch staged = {.count = 1, .entries = {{.index = MSR_KERNEL_GS_BASE}}};
    check(ioctl(cpu, KVM_GET_MSRS, &staged) == 1 && staged.entries[0].data == GS_BASE_INITIAL,
          "read the boot MSR before first entry");
}

static void update_msrs(int cpu, const unsigned char *ram)
{
    uint32_t gs_base;
    uint64_t start, end;
    struct pvkvm_msr_batch readback = {
        .count = 4, .entries = {
            {.index = MSR_KERNEL_GS_BASE}, {.index = 0x10}, {.index = UINT32_MAX},
            {.index = MSR_KERNEL_GS_BASE, .data = 0x55},
        },
    };
    const struct pvkvm_msr_batch update = {
        .count = 3, .entries = {
            {.index = MSR_KERNEL_GS_BASE, .data = GS_BASE_FOR_RESUME}, {.index = UINT32_MAX},
            {.index = MSR_KERNEL_GS_BASE, .data = 0x55},
        },
    };

    memcpy(&gs_base, ram + 0xc0, sizeof(gs_base));
    memcpy(&start, ram + 0xc8, sizeof(start));
    memcpy(&end, ram + 0xd0, sizeof(end));
    check(gs_base == GS_BASE_INITIAL && start >= TSC_START && start - TSC_START < (1ULL << 34) && end > start,
          "observe the configured GS base and a progressing TSC inside the child");
    check(ioctl(cpu, KVM_GET_MSRS, &readback) == 2 &&
          readback.entries[0].data == GS_BASE_FROM_GUEST && readback.entries[1].data >= end &&
          readback.entries[3].data == 0x55,
          "read live MSRs and stop at the first unsupported index");
    check(ioctl(cpu, KVM_SET_MSRS, &update) == 1, "set the supported prefix of a mixed MSR batch");
}

static void check_resumed_msrs(int cpu, const unsigned char *data)
{
    uint32_t gs_base;
    struct pvkvm_msr_batch readback = {.count = 1, .entries = {{.index = MSR_KERNEL_GS_BASE}}};

    memcpy(&gs_base, data + 0xc0, sizeof(gs_base));
    check(gs_base == GS_BASE_FOR_RESUME && ioctl(cpu, KVM_GET_MSRS, &readback) == 1 &&
          readback.entries[0].data == GS_BASE_FOR_RESUME,
          "the resumed child observed the updated MSR");
    puts("PASS x86 boot MSRs reached the parent worker");
}

static void get_supported_cpuid(int kvm, struct pvkvm_cpuid_table *table)
{
    struct kvm_cpuid2 small = {0};
    check(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, &small) == -1 && errno == E2BIG,
          "reject a short supported CPUID buffer");
    table->count = PVKVM_CPUID_MAX;
    check(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, table) == 0 &&
          table->count >= 4 && table->count <= PVKVM_CPUID_MAX - 2,
          "read the engine's supported CPUID table");
    bool vendor = false, features = false;
    for (unsigned int i = 0; i < table->count; i++) {
        const struct kvm_cpuid_entry2 *entry = &table->entries[i];
        if (entry->function == 0)
            vendor = entry->eax >= 1 && entry->ebx && entry->ecx && entry->edx;
        if (entry->function == 1)
            features = entry->eax != 0;
        check(entry->function != CPUID_TEST_FUNCTION, "choose an unused synthetic CPUID function");
    }
    check(vendor && features, "read native CPU identification and features");
}

static void install_cpuid(int cpu, unsigned int id, const struct pvkvm_cpuid_table *supported)
{
    struct pvkvm_cpuid_table configured = *supported;
    for (unsigned int i = 1; i <= 2; i++) {
        configured.entries[configured.count++] = (struct kvm_cpuid_entry2){
            .function = CPUID_TEST_FUNCTION, .index = i, .flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
            .eax = CPUID_TEST_RESULT + 16 * id + i,
        };
    }
    check(ioctl(cpu, KVM_SET_CPUID2, &configured) == 0, "install a per-vCPU CPUID profile");
    struct kvm_cpuid2 small = {0};
    check(ioctl(cpu, KVM_GET_CPUID2, &small) == -1 && errno == E2BIG, "reject a short vCPU CPUID buffer");
    struct pvkvm_cpuid_table readback = {.count = PVKVM_CPUID_MAX};
    check(ioctl(cpu, KVM_GET_CPUID2, &readback) == 0 && readback.count == configured.count,
          "read the configured vCPU CPUID table");
    check(!memcmp(readback.entries + readback.count - 2, configured.entries + configured.count - 2,
                  2 * sizeof(readback.entries[0])), "read back both indexed CPUID results");
}

static void check_cpuid_result(const unsigned char *ram, unsigned int id,
                               const struct pvkvm_cpuid_table *supported)
{
    uint32_t first, second, absent;
    memcpy(&first, ram + 0xe0, sizeof(first));
    memcpy(&second, ram + 0xe4, sizeof(second));
    memcpy(&absent, ram + 0xe8, sizeof(absent));
    check(first == CPUID_TEST_RESULT + 16 * id + 1 && second == CPUID_TEST_RESULT + 16 * id + 2,
          "the running vCPU selected its own configured CPUID subleaves");
    const struct kvm_cpuid_entry2 *root = NULL;
    for (unsigned int i = 0; i < supported->count; i++)
        if (!supported->entries[i].function)
            root = &supported->entries[i];
    check(root != NULL, "find the basic CPUID range for the running vCPU");
    const uint32_t vendor[] = {root->ebx, root->edx, root->ecx};
    uint32_t expected = 0;
    if (memcmp(vendor, "AuthenticAMD", sizeof(vendor)) && memcmp(vendor, "HygonGenuine", sizeof(vendor))) {
        for (unsigned int i = 0; i < supported->count; i++) {
            const struct kvm_cpuid_entry2 *entry = &supported->entries[i];
            if (entry->function == root->eax && (!(entry->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) || !entry->index)) {
                expected = entry->eax;
                break;
            }
        }
    }
    check(absent == expected, "use the configured vendor's out-of-range CPUID behavior");
}

static void check_mmio_write(const struct kvm_run *run, uint64_t address, unsigned int length, uint64_t value)
{
    check(run->exit_reason == KVM_EXIT_MMIO && run->mmio.is_write &&
          run->mmio.phys_addr == address && run->mmio.len == length &&
          !memcmp(run->mmio.data, &value, length), "return a guest physical MMIO write and its exact bytes");
}

static void check_mmio_writes(int cpu, const struct kvm_run *run, const unsigned char *ram)
{
    const struct {
        uint64_t address;
        unsigned int length;
        uint64_t value;
    } expected[] = {
        {MMIO_BASE + 0x10, 1, 0x39},
        {MMIO_BASE + 0x14, 4, 0x43658709},
        {MMIO_BASE + 0x18, 8, 0x1122334455667788ULL},
    };

    for (unsigned int i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        timed_run(cpu);
        check_mmio_write(run, expected[i].address, expected[i].length, expected[i].value);
        check(ram[0xf0] == i, "stop before the instruction following each MMIO write");
    }
}

enum { MATCHED_MMIO, OTHER_DATA, WILDCARD_MMIO, MATCHED_PIO, EVENT_COUNT };

struct ioevent_test {
    struct kvm_ioeventfd settings[EVENT_COUNT];
};

static struct ioevent_test install_ioeventfds(int vm)
{
    struct ioevent_test test = {.settings = {
        [MATCHED_MMIO] = {.addr = MMIO_BASE + 0x10, .len = 1, .datamatch = 0x39, .flags = KVM_IOEVENTFD_FLAG_DATAMATCH},
        [OTHER_DATA] = {.addr = MMIO_BASE + 0x10, .len = 1, .datamatch = 0x3a, .flags = KVM_IOEVENTFD_FLAG_DATAMATCH},
        [WILDCARD_MMIO] = {.addr = MMIO_BASE + 0x14},
        [MATCHED_PIO] = {.addr = PVKVM_IO_PORT, .len = 1, .datamatch = 0xcc,
                         .flags = KVM_IOEVENTFD_FLAG_DATAMATCH | KVM_IOEVENTFD_FLAG_PIO},
    }};

    check(ioctl(vm, KVM_CHECK_EXTENSION, KVM_CAP_IOEVENTFD) == 1 &&
          ioctl(vm, KVM_CHECK_EXTENSION, KVM_CAP_IOEVENTFD_ANY_LENGTH) == 1, "query eventfd write capabilities");
    for (unsigned int i = 0; i < EVENT_COUNT; i++) {
        test.settings[i].fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        check(test.settings[i].fd >= 0 && ioctl(vm, KVM_IOEVENTFD, &test.settings[i]) == 0,
              "register a guest VMM eventfd");
    }
    check(ioctl(vm, KVM_IOEVENTFD, &test.settings[MATCHED_MMIO]) == -1 && errno == EEXIST,
          "reject a duplicate eventfd filter");
    return test;
}

static void check_ioeventfds(int vm, int cpu, const struct kvm_run *run,
                             const unsigned char *ram, const struct ioevent_test *test)
{
    eventfd_t value;

    timed_run(cpu);
    check_mmio_write(run, MMIO_BASE + 0x18, 8, 0x1122334455667788ULL);
    check(ram[0xf0] == 2, "continue after the three matching eventfd writes");
    for (unsigned int i = 0; i < EVENT_COUNT; i++) {
        if (i == OTHER_DATA) {
            check(eventfd_read(test->settings[i].fd, &value) == -1 && errno == EAGAIN,
                  "do not signal a different data filter at the same address");
        } else {
            check(eventfd_read(test->settings[i].fd, &value) == 0 && value == 1,
                  "signal the actual guest eventfd once for the matching write");
        }
    }
    struct kvm_ioeventfd removal = test->settings[MATCHED_MMIO];
    removal.flags |= KVM_IOEVENTFD_FLAG_DEASSIGN;
    removal.fd = test->settings[OTHER_DATA].fd;
    check(ioctl(vm, KVM_IOEVENTFD, &removal) == -1 && errno == ENOENT, "match eventfd identity on deassignment");
    removal.fd = test->settings[MATCHED_MMIO].fd;
    check(ioctl(vm, KVM_IOEVENTFD, &removal) == 0, "deassign the matching MMIO eventfd");
    check(ioctl(vm, KVM_IOEVENTFD, &removal) == -1 && errno == ENOENT, "reject repeated eventfd deassignment");

    timed_run(cpu);
    check_mmio_write(run, MMIO_BASE + 0x10, 1, 0x39);
    check(ram[0xf0] == 3, "return the write after eventfd deassignment");
    check(eventfd_read(test->settings[MATCHED_MMIO].fd, &value) == -1 && errno == EAGAIN,
          "do not notify a deassigned eventfd");
    for (unsigned int i = 0; i < EVENT_COUNT; i++)
        close(test->settings[i].fd);
    puts("PASS KVM_IOEVENTFD signaled matched MMIO and PIO writes");
}

static void complete_mmio_reads(int cpu, struct kvm_run *run, const unsigned char *ram, uint64_t entry_base)
{
    const uint32_t first_value = MMIO_FIRST_VALUE;
    const uint64_t second_value = MMIO_SECOND_VALUE;
    uint32_t first;
    uint64_t second;
    struct kvm_regs stopped;

    timed_run(cpu);
    check(run->exit_reason == KVM_EXIT_MMIO && !run->mmio.is_write &&
          run->mmio.phys_addr == MMIO_BASE + 0x24 && run->mmio.len == sizeof(first_value),
          "exit for a four-byte MMIO read");
    check(ioctl(cpu, KVM_GET_REGS, &stopped) == 0 && stopped.rip >= entry_base + MMIO_READ_OFFSET,
          "read the vCPU register state during MMIO completion");
    memcpy(&first, ram + 0x100, sizeof(first));
    memcpy(&second, ram + 0x108, sizeof(second));
    check(!first && !second, "stop at the first read before consuming any data");
    memcpy(run->mmio.data, &first_value, sizeof(first_value));

    timed_run(cpu);
    check(run->exit_reason == KVM_EXIT_MMIO && !run->mmio.is_write &&
          run->mmio.phys_addr == MMIO_BASE + 0x28 && run->mmio.len == sizeof(second_value),
          "exit for an eight-byte MMIO read");
    check(ioctl(cpu, KVM_GET_REGS, &stopped) == 0 && stopped.rip >= entry_base + MMIO_READ_OFFSET,
          "read the vCPU register state during the second MMIO read");
    memcpy(&first, ram + 0x100, sizeof(first));
    memcpy(&second, ram + 0x108, sizeof(second));
    check(first == first_value && !second, "continue from the first read and stop at the second");
    memcpy(run->mmio.data, &second_value, sizeof(second_value));
}

struct interrupt_test {
    uint32_t *counter;
    uint32_t baseline;
    pthread_t runner;
    bool long_run;
};

static void signal_handler(int signo)
{
    (void)signo;
}

static void *signal_running_vcpu(void *opaque)
{
    struct interrupt_test *test = opaque;
    const struct timespec retry = {.tv_nsec = 1000000};
    for (unsigned int attempt = 0; attempt < 2000 &&
         __atomic_load_n(test->counter, __ATOMIC_RELAXED) == test->baseline; attempt++)
        nanosleep(&retry, NULL);
    check(__atomic_load_n(test->counter, __ATOMIC_RELAXED) != test->baseline,
          "observe child instructions before sending the signal");
    if (test->long_run) {
        const struct timespec hold = {.tv_sec = 5, .tv_nsec = 500000000};
        check(nanosleep(&hold, NULL) == 0, "allow a sustained active KVM_RUN before sending the signal");
    }
    check(pthread_kill(test->runner, SIGUSR1) == 0, "signal the running KVM ioctl thread");
    return NULL;
}

static void interrupt_child(int cpu, uint32_t *counter, uint64_t gpa, bool long_run)
{
    struct interrupt_test test = {.counter = counter, .runner = pthread_self(),
                                  .long_run = long_run,
                                  .baseline = __atomic_load_n(counter, __ATOMIC_RELAXED)};
    pthread_t sender;
    check(pthread_create(&sender, NULL, signal_running_vcpu, &test) == 0, "start the signal sender");
    check(ioctl(cpu, KVM_RUN, 0) == -1 && errno == EINTR, "interrupt an actively running child");
    check(pthread_join(sender, NULL) == 0, "join the signal sender");

    struct kvm_regs paused;
    check(ioctl(cpu, KVM_GET_REGS, &paused) == 0 && paused.rip >= gpa + 0x60 && paused.rip < gpa + 0x71,
          "read the stopped child's actual loop position");
    uint32_t before = __atomic_load_n(counter, __ATOMIC_RELAXED);
    const struct timespec settle = {.tv_nsec = 25000000};
    check(nanosleep(&settle, NULL) == 0, "observe the paused child");
    check(before != test.baseline && __atomic_load_n(counter, __ATOMIC_RELAXED) == before,
          "confirmed stop prevents further shared-memory writes");
}

static void interrupt_and_resume(int cpu, unsigned char *data, uint64_t gpa)
{
    struct sigaction action = {.sa_handler = signal_handler};
    check(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, NULL) == 0,
          "install signal handler for running KVM ioctl");
    uint32_t *counter = (uint32_t *)(data + 0x84);
    for (int attempt = 0; attempt < TEST_INTERRUPTS; attempt++)
        interrupt_child(cpu, counter, gpa, attempt == 0);
    data[0x83] = 1;
}

int main(int argc, char **argv)
{
    bool split_slot = argc >= 3 && !strcmp(argv[2], "split");
    bool protected_mode = split_slot || (argc >= 3 && !strcmp(argv[2], "protected"));
    bool interrupt_run = false;
    bool two_vcpus = false;
    bool long_mode = false;
    bool fpu = false;
    bool msrs = false;
    bool cpuid = false;
    bool mmio = false;
    bool mmio_read = false;
    bool ioeventfd = false;
    check(argc == 2 || protected_mode, "specify RAM pages and optional protected or split mode");
    for (int i = 3; i < argc; i++) {
        if (!interrupt_run && !strcmp(argv[i], "interrupt"))
            interrupt_run = true;
        else if (!two_vcpus && !strcmp(argv[i], "smp"))
            two_vcpus = true;
        else if (!long_mode && !strcmp(argv[i], "long"))
            long_mode = true;
        else if (!fpu && !strcmp(argv[i], "fpu"))
            fpu = true;
        else if (!msrs && !strcmp(argv[i], "msrs"))
            msrs = true;
        else if (!cpuid && !strcmp(argv[i], "cpuid"))
            cpuid = true;
        else if (!mmio && !strcmp(argv[i], "mmio"))
            mmio = true;
        else if (!mmio_read && !strcmp(argv[i], "mmio-read"))
            mmio_read = true;
        else if (!ioeventfd && !strcmp(argv[i], "ioeventfd"))
            ioeventfd = true;
        else
            check(false, "invalid execution option");
    }
    char *end;
    errno = 0;
    long count = strtol(argv[1], &end, 10);
    check(!errno && !*end && count > 0 && count <= PVKVM_MAX_PAGES, "select the RAM page count");
    check(protected_mode || count <= PVKVM_REAL_MODE_MAX_PAGES, "select protected mode for a large slot");
    check(!split_slot || count >= 2, "split mode needs at least two RAM pages");
    check(!long_mode || (!two_vcpus && count >= (split_slot ? 8 : 4)), "reserve four low pages for long mode");
    check(!fpu || long_mode, "exercise floating-point state in long mode");
    check(!msrs || (long_mode && !fpu), "exercise boot MSRs in a separate long-mode run");
    check(!cpuid || (protected_mode && !fpu && !msrs), "exercise CPUID in a separate protected-mode run");
    check(!mmio || (long_mode && !cpuid && !fpu && !msrs), "exercise MMIO in a separate long-mode run");
    check(!mmio_read || mmio, "test MMIO reads after the write exits");
    check(!ioeventfd || mmio, "test eventfd notifications in the MMIO fixture");
    size_t pages = count;
    size_t ram_bytes = pages * 4096;
    uint64_t gpa = protected_mode ? PROTECTED_SLOT_GPA : PVKVM_GUEST_START;
    uint64_t middle_page = gpa + (pages / 2) * 4096;
    uint64_t last_page = gpa + ram_bytes - 4096;
    if (split_slot) {
        middle_page = SPLIT_SLOT_GPA;
        last_page = SPLIT_SLOT_GPA + (pages - pages / 2 - 1) * 4096;
    }
    uint64_t entry_base = long_mode ? LONG_ALIAS : gpa;
    uint64_t middle_address = long_mode ? LONG_ALIAS + HUGE_PAGE_SIZE + (middle_page % HUGE_PAGE_SIZE) : middle_page;
    uint64_t data_address = long_mode ? LONG_ALIAS + 2 * HUGE_PAGE_SIZE + (last_page % HUGE_PAGE_SIZE) : last_page;
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0, "open /dev/kvm");
    check(ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "API version");
    check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY) == 1 &&
          ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_NR_MEMSLOTS) >= PVKVM_MAX_SLOTS,
          "query system KVM memory capabilities");
    struct pvkvm_cpuid_table supported = {0};
    if (cpuid)
        get_supported_cpuid(kvm, &supported);
    int size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    check(size >= (int)sizeof(struct kvm_run), "run mapping size");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0 && (fcntl(vm, F_GETFD) & FD_CLOEXEC), "VM file descriptor");
    check(ioctl(vm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY) == 1,
          "query the VM's memory capability");
    unsigned char *ram = mmap(NULL, ram_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(ram != MAP_FAILED, "map client RAM");
    volatile unsigned char *scratch = NULL;
    size_t gap = 32 * 4096;
    size_t separated_pages = pages > 129 ? 128 : pages - 1;
    size_t scratch_bytes = separated_pages * gap;
    if (scratch_bytes) {
        volatile unsigned char *touch = ram;
        scratch = mmap(NULL, scratch_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        check(scratch != MAP_FAILED, "allocate intervening pages");
        for (size_t i = 0; i < separated_pages; i++) {
            touch[(pages - 1 - i) * 4096] = 0;
            for (size_t byte = i * gap; byte < (i + 1) * gap; byte += 4096)
                scratch[byte] = 1;
        }
        for (size_t i = 0; i < pages - separated_pages; i++)
            touch[i * 4096] = 0;
    }
    size_t first_bytes = split_slot ? (pages / 2) * 4096 : ram_bytes;
    if (split_slot) {
        struct kvm_userspace_memory_region second = {
            .slot = 5, .guest_phys_addr = SPLIT_SLOT_GPA, .memory_size = ram_bytes - first_bytes,
            .userspace_addr = (unsigned long)(ram + first_bytes),
        };
        check(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &second) == 0, "register the high RAM slot first");
        struct kvm_userspace_memory_region overlapping = second;
        overlapping.slot = 6;
        overlapping.memory_size = 4096;
        check(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &overlapping) == -1 && errno == EEXIST,
              "reject an overlapping guest-physical slot");
    }
    struct kvm_userspace_memory_region region = {
        .guest_phys_addr = gpa, .memory_size = first_bytes, .userspace_addr = (unsigned long)ram,
    };
    check(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0, "register client RAM");
    if (scratch)
        check(munmap((void *)scratch, scratch_bytes) == 0, "release intervening pages");
    const unsigned char code[] = {
        0xba, 0, pages, 0x8e, 0xda,   /* mov dx, pages * 0x100; mov ds, dx */
        0x66, 0x0f, 0x01, 0x16, 0x00, 0x01, /* lgdt ds:[0x100] with a 32-bit base */
        0x66, 0xbb, 0xef, 0xcd, 0xab, 0x89,  /* mov ebx, 0x89abcdef */
        0x0f, 0x22, 0xd3,                    /* mov cr2, ebx */
        0x2e, 0xc6, 0x06, 0x90, 0x10, 0x57, /* mov byte cs:[0x1090], 0x57 */
        0xc6, 0x06, 0x80, 0x00, 0x56, /* mov byte ds:[0x80], 0x56 */
        0xb9, 0x57, 0x13,             /* mov cx, 0x1357 */
        0x14, 0x00, 0xe6, 0x30,       /* adc al, 0; out 0x30, al */
        0xf4,                         /* hlt */
    };
    const unsigned char resumed[] = {
        0xa0, 0x81, 0x00,             /* mov al, ds:[0x81] */
        0xa2, 0x82, 0x00,             /* mov ds:[0x82], al */
        0x30, 0xd8,                   /* xor al, bl */
        0xb9, 0x68, 0x24,             /* mov cx, 0x2468 */
        0xe6, 0x30, 0xf4,             /* out 0x30, al; hlt */
    };
    const unsigned char flat_code[] = {
        0xc6, 0x87, 0x90, 0, 0, 0, 0x57, /* mov byte [edi+0x90], 0x57 */
        0xc6, 0x46, 0x78, 0xb3,          /* mov byte [esi+0x78], 0xb3 */
        0xc6, 0x83, 0x80, 0, 0, 0, 0x56, /* mov byte [ebx+0x80], 0x56 */
        0xb9, 0x57, 0x13, 0, 0,          /* mov ecx, 0x1357 */
        0xbe, 0xef, 0xcd, 0xab, 0x89,    /* mov esi, 0x89abcdef */
        0x0f, 0x22, 0xd6,               /* mov cr2, esi */
        0x14, 0x00, 0xe6, 0x30, 0xf4,   /* adc al, 0; out 0x30, al; hlt */
    };
    const unsigned char flat_resumed[] = {
        0x8a, 0x87, 0x81, 0, 0, 0,       /* mov al, [edi+0x81] */
        0x88, 0x87, 0x82, 0, 0, 0,       /* mov [edi+0x82], al */
        0x30, 0xd8,                     /* xor al, bl */
        0xb9, 0x68, 0x24, 0, 0,          /* mov ecx, 0x2468 */
        0xe6, 0x30, 0xf4,                /* out 0x30, al; hlt */
    };
    const unsigned char flat_interruptible[] = {
        0xff, 0x87, 0x84, 0, 0, 0,       /* inc dword [edi+0x84] */
        0x80, 0xbf, 0x83, 0, 0, 0, 0,    /* cmp byte [edi+0x83], 0 */
        0x74, 0xf1,                     /* je to the increment */
        0xeb, 0xcf,                     /* jmp to the resumed code at 0x40 */
    };
    const unsigned char second_cpu_code[] = {
        0xb9, 0x44, 0x33, 0, 0,         /* mov ecx, 0x3344 */
        0x8a, 0x87, 0x80, 0, 0, 0,     /* mov al, [edi+0x80] */
        0x88, 0x87, 0xa0, 0, 0, 0,     /* mov [edi+0xa0], al */
        0xe6, 0x30,                    /* out 0x30, al */
        0xc6, 0x87, 0xa1, 0, 0, 0, 0xff, /* mov byte [edi+0xa1], 0xff */
        0xf4,
    };
    const unsigned char cpuid_entry[] = {
        0x53,                               /* push bx (32-bit or 64-bit) */
        0xb8, 0x7e, 0, 0, 0x40,            /* mov eax, 0x4000007e */
        0xb9, 0x01, 0, 0, 0,               /* mov ecx, 1 */
        0x0f, 0xa2,                         /* cpuid */
        0x89, 0x87, 0xe0, 0, 0, 0,          /* mov [edi+0xe0], eax */
        0xb8, 0x7e, 0, 0, 0x40,            /* mov eax, 0x4000007e */
        0xb9, 0x02, 0, 0, 0,               /* mov ecx, 2 */
        0x0f, 0xa2,                         /* cpuid */
        0x89, 0x87, 0xe4, 0, 0, 0,          /* mov [edi+0xe4], eax */
        0xb8, 0xff, 0xff, 0xff, 0x3f,       /* mov eax, 0x3fffffff */
        0x31, 0xc9,                         /* xor ecx, ecx */
        0x0f, 0xa2,                         /* cpuid */
        0x89, 0x87, 0xe8, 0, 0, 0,          /* mov [edi+0xe8], eax */
        0x5b,                               /* pop bx (32-bit or 64-bit) */
        0xb8, 0x41, 0, 0, 0, 0xf9,          /* mov eax, 0x41; stc */
    };
    unsigned char *data = ram + ram_bytes - 4096;
    unsigned char *middle = ram + (pages / 2) * 4096;
    const unsigned char gdtr[] = {0x2f, 0x00, 0x80, 0x34, 0x12, 0x00};
    const uint64_t gdt[] = { 0, long_mode ? 0x00af9b000000ffff : 0x00cf9b000000ffff, 0x00cf93000000ffff };
    if (protected_mode) {
        const unsigned char long_prelude[] = {0x4d, 0x89, 0xf8}; /* mov r8, r15 */
        const unsigned char fpu_entry[] = {
            0x0f, 0x20, 0xe0,                   /* mov rax, cr4 */
            0x0d, 0, 0x02, 0, 0,               /* or eax, 0x200 (OSFXSR) */
            0x0f, 0x22, 0xe0,                   /* mov cr4, rax */
            0x0f, 0xae, 0x97, 0xbc, 0, 0, 0,   /* ldmxcsr [rdi+0xbc] */
            0x66, 0x0f, 0x74, 0xc0,             /* pcmpeqb xmm0, xmm0 */
            0x66, 0x0f, 0xfc, 0xc0,             /* paddb xmm0, xmm0 */
            0xd9, 0xaf, 0xb8, 0, 0, 0,          /* fldcw [rdi+0xb8] */
            0xd9, 0xbf, 0xb0, 0, 0, 0,          /* fnstcw [rdi+0xb0] */
            0xd9, 0xe8,                         /* fld1 */
            0xdb, 0x9f, 0xb4, 0, 0, 0,          /* fistp dword [rdi+0xb4] */
            0xd9, 0xe8,                         /* fld1, leave a nonempty stack */
            0xb8, 0x41, 0, 0, 0, 0xf9,          /* mov eax, 0x41; stc */
        };
        const unsigned char fpu_resume[] = {
            0x66, 0x0f, 0xfc, 0xc0,             /* paddb xmm0, xmm0 */
            0xd9, 0xbf, 0xb0, 0, 0, 0,          /* fnstcw [rdi+0xb0] */
            0xdb, 0x9f, 0xb4, 0, 0, 0,          /* fistp dword [rdi+0xb4] */
            0x0f, 0xae, 0x9f, 0xbc, 0, 0, 0,   /* stmxcsr [rdi+0xbc] */
        };
        const unsigned char msr_entry[] = {
            0xb9, 0x02, 0x01, 0x00, 0xc0,        /* mov ecx, MSR_KERNEL_GS_BASE */
            0x0f, 0x32,                         /* rdmsr */
            0x89, 0x87, 0xc0, 0, 0, 0,          /* mov [rdi+0xc0], eax */
            0xb8, 0x78, 0x56, 0x34, 0x12,        /* mov eax, 0x12345678 */
            0x31, 0xd2, 0x0f, 0x30,             /* xor edx, edx; wrmsr */
            0x0f, 0x31,                         /* rdtsc */
            0x89, 0x87, 0xc8, 0, 0, 0,          /* mov [rdi+0xc8], eax */
            0x89, 0x97, 0xcc, 0, 0, 0,          /* mov [rdi+0xcc], edx */
            0x41, 0xb8, 0x00, 0x10, 0, 0,       /* mov r8d, 4096 */
            0x41, 0xff, 0xc8, 0x75, 0xfb,        /* dec r8d; jnz to the decrement */
            0x0f, 0x31,                         /* rdtsc */
            0x89, 0x87, 0xd0, 0, 0, 0,          /* mov [rdi+0xd0], eax */
            0x89, 0x97, 0xd4, 0, 0, 0,          /* mov [rdi+0xd4], edx */
            0xb8, 0x41, 0, 0, 0, 0xf9,          /* mov eax, 0x41; stc */
        };
        const unsigned char msr_resume[] = {
            0xb9, 0x02, 0x01, 0x00, 0xc0,        /* mov ecx, MSR_KERNEL_GS_BASE */
            0x0f, 0x32,                         /* rdmsr */
            0x89, 0x87, 0xc0, 0, 0, 0,          /* mov [rdi+0xc0], eax */
        };
        const unsigned char mmio_entry[] = {
            0x49, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0,     /* mov r9, virtual MMIO address */
            0x41, 0xc6, 0x41, 0x10, 0x39,           /* mov byte [r9+0x10], 0x39 */
            0xc6, 0x87, 0xf0, 0, 0, 0, 1,          /* mov byte [rdi+0xf0], 1 */
            0x41, 0xc7, 0x41, 0x14, 0x09, 0x87, 0x65, 0x43, /* mov dword [r9+0x14], 0x43658709 */
            0xc6, 0x87, 0xf0, 0, 0, 0, 2,          /* mov byte [rdi+0xf0], 2 */
            0x49, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, /* mov r8, 0x1122334455667788 */
            0x4d, 0x89, 0x41, 0x18,                 /* mov [r9+0x18], r8 */
            0xc6, 0x87, 0xf0, 0, 0, 0, 3,          /* mov byte [rdi+0xf0], 3 */
            0xb8, 0x41, 0, 0, 0, 0xf9,              /* mov eax, 0x41; stc */
        };
        const unsigned char mmio_read_code[] = {
            0x41, 0x8b, 0x41, 0x24,              /* mov eax, [r9+0x24] */
            0x89, 0x87, 0x00, 0x01, 0, 0,       /* mov [rdi+0x100], eax */
            0x49, 0x8b, 0x41, 0x28,              /* mov rax, [r9+0x28] */
            0x48, 0x89, 0x87, 0x08, 0x01, 0, 0, /* mov [rdi+0x108], rax */
            0xb8, 0x41, 0, 0, 0, 0xf9,           /* mov eax, 0x41; stc */
        };
        const unsigned char pio_notification[] = {0xb0, 0xcc, 0xe6, 0x30}; /* mov al, 0xcc; out 0x30, al */
        const unsigned char deassigned_write[] = {0x41, 0xc6, 0x41, 0x10, 0x39}; /* mov byte [r9+0x10], 0x39 */
        size_t startup = 0x10;
        size_t resume = 0x40;
        if (fpu) {
            const uint16_t control = 0x77f;
            const uint32_t mxcsr = 0x3f80;
            memcpy(ram + 0xb8, &control, sizeof(control));
            memcpy(ram + 0xbc, &mxcsr, sizeof(mxcsr));
            memcpy(ram + FPU_ENTRY_OFFSET, fpu_entry, sizeof(fpu_entry));
            install_jump(ram, FPU_ENTRY_OFFSET + sizeof(fpu_entry), startup);
            install_jump(ram, resume, FPU_RESUME_OFFSET);
            resume += 5;
            memcpy(ram + FPU_RESUME_OFFSET, fpu_resume, sizeof(fpu_resume));
            install_jump(ram, FPU_RESUME_OFFSET + sizeof(fpu_resume), resume);
        } else if (msrs) {
            memcpy(ram + MSR_ENTRY_OFFSET, msr_entry, sizeof(msr_entry));
            install_jump(ram, MSR_ENTRY_OFFSET + sizeof(msr_entry), startup);
            install_jump(ram, resume, MSR_RESUME_OFFSET);
            resume += 5;
            memcpy(ram + MSR_RESUME_OFFSET, msr_resume, sizeof(msr_resume));
            install_jump(ram, MSR_RESUME_OFFSET + sizeof(msr_resume), resume);
        } else if (mmio) {
            const uint64_t address = LONG_ALIAS + 3 * HUGE_PAGE_SIZE;
            int after_writes = mmio_read ? MMIO_READ_OFFSET : (int)startup;
            memcpy(ram + MMIO_ENTRY_OFFSET, mmio_entry, sizeof(mmio_entry));
            memcpy(ram + MMIO_ENTRY_OFFSET + 2, &address, sizeof(address));
            install_jump(ram, MMIO_ENTRY_OFFSET + sizeof(mmio_entry),
                         ioeventfd ? MMIO_DEASSIGNED_OFFSET : after_writes);
            if (ioeventfd) {
                memcpy(ram + PIO_EVENTFD_OFFSET, pio_notification, sizeof(pio_notification));
                install_jump(ram, PIO_EVENTFD_OFFSET + sizeof(pio_notification), MMIO_ENTRY_OFFSET);
                memcpy(ram + MMIO_DEASSIGNED_OFFSET, deassigned_write, sizeof(deassigned_write));
                install_jump(ram, MMIO_DEASSIGNED_OFFSET + sizeof(deassigned_write), after_writes);
            }
            if (mmio_read) {
                memcpy(ram + MMIO_READ_OFFSET, mmio_read_code, sizeof(mmio_read_code));
                install_jump(ram, MMIO_READ_OFFSET + sizeof(mmio_read_code), startup);
            }
        }
        if (long_mode) {
            setup_page_tables(ram, gpa, middle_page, last_page, mmio);
            memcpy(ram + startup, long_prelude, sizeof(long_prelude));
            startup += sizeof(long_prelude);
        }
        memcpy(ram + startup, flat_code, sizeof(flat_code));
        memcpy(ram + resume, flat_resumed, sizeof(flat_resumed));
        if (interrupt_run)
            memcpy(ram + 0x60, flat_interruptible, sizeof(flat_interruptible));
        memcpy(ram + GDT_OFFSET, gdt, sizeof(gdt));
    } else {
        memcpy(ram + 0x10, code, sizeof(code));
        memcpy(ram + 0x40, resumed, sizeof(resumed));
        memcpy(data + 0x100, gdtr, sizeof(gdtr));
    }
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    check(cpu >= 0 && (fcntl(cpu, F_GETFD) & FD_CLOEXEC), "vCPU file descriptor");
    check(ioctl(vm, KVM_CREATE_VCPU, 0) == -1 && errno == EEXIST, "reject duplicate vCPU");
    if (cpuid) {
        memcpy(ram + CPUID_ENTRY_OFFSET, cpuid_entry, sizeof(cpuid_entry));
        install_jump(ram, CPUID_ENTRY_OFFSET + sizeof(cpuid_entry), 0x10);
        install_cpuid(cpu, 0, &supported);
    }
    struct kvm_run *run = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
    check(run != MAP_FAILED, "map kvm_run");
    struct kvm_regs regs = {.rax = 0x41, .rip = entry_base + 0x10, .rflags = 3};
    if (fpu)
        regs.rip = entry_base + FPU_ENTRY_OFFSET;
    if (msrs)
        regs.rip = entry_base + MSR_ENTRY_OFFSET;
    if (mmio)
        regs.rip = entry_base + (ioeventfd ? PIO_EVENTFD_OFFSET : MMIO_ENTRY_OFFSET);
    if (cpuid) {
        regs.rip = entry_base + CPUID_ENTRY_OFFSET;
        regs.rsp = entry_base + 0xf00;
    }
    if (protected_mode) {
        regs.rbx = data_address;
        regs.rdi = entry_base;
        regs.rsi = middle_address;
    }
    if (long_mode)
        regs.r15 = LONG_REGISTER;
    check(ioctl(cpu, KVM_SET_REGS, &regs) == 0, "set initial registers");
    struct kvm_regs readback;
    check(ioctl(cpu, KVM_GET_REGS, &readback) == 0 && !memcmp(&readback, &regs, sizeof(regs)),
          "read back initial registers");
    select_segments(cpu, protected_mode, long_mode, gpa);
    if (fpu)
        prepare_fpu(cpu);
    if (msrs)
        prepare_msrs(kvm, cpu);
    int other_cpu = -1;
    struct kvm_run *other_run = NULL;
    if (two_vcpus) {
        check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_MAX_VCPUS) >= 2, "query two-vCPU support");
        memcpy(ram + SECOND_CPU_OFFSET, second_cpu_code, sizeof(second_cpu_code));
        other_cpu = ioctl(vm, KVM_CREATE_VCPU, 1);
        check(other_cpu >= 0 && (fcntl(other_cpu, F_GETFD) & FD_CLOEXEC), "second vCPU file descriptor");
        other_run = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, other_cpu, 0);
        check(other_run != MAP_FAILED, "map second kvm_run");
        struct kvm_regs other_regs = {.rdi = last_page, .rip = gpa + SECOND_CPU_OFFSET, .rflags = 2};
        if (cpuid) {
            memcpy(ram + CPUID_SECOND_OFFSET, cpuid_entry, sizeof(cpuid_entry));
            install_jump(ram, CPUID_SECOND_OFFSET + sizeof(cpuid_entry), SECOND_CPU_OFFSET);
            install_cpuid(other_cpu, 1, &supported);
            other_regs.rip = gpa + CPUID_SECOND_OFFSET;
            other_regs.rsp = gpa + 0xf00;
        }
        check(ioctl(other_cpu, KVM_SET_REGS, &other_regs) == 0, "set second vCPU registers");
        select_segments(other_cpu, true, false, gpa);
    }
    struct ioevent_test notifications;
    if (ioeventfd)
        notifications = install_ioeventfds(vm);
    else
        close(vm);
    run->immediate_exit = 1;
    check(ioctl(cpu, KVM_RUN, 0) == -1 && errno == EINTR, "immediate exit");
    run->immediate_exit = 0;
    if (ioeventfd) {
        check_ioeventfds(vm, cpu, run, ram, &notifications);
        close(vm);
    } else if (mmio) {
        check_mmio_writes(cpu, run, ram);
    }
    if (mmio_read)
        complete_mmio_reads(cpu, run, ram, entry_base);
    unsigned long long first = timed_run(cpu);
    check_output(run, size, 0x42);
    struct kvm_regs observed = check_registers(cpu, 0x42, 0x1357, entry_base);
    if (long_mode)
        check(observed.r8 == LONG_REGISTER && observed.r15 == LONG_REGISTER, "execute a 64-bit register transfer");
    struct kvm_sregs sregs;
    check(ioctl(cpu, KVM_GET_SREGS, &sregs) == 0, "read actual special registers after exit");
    check(sregs.cr2 == 0x89abcdef && sregs.ds.present && !sregs.ds.unusable,
          "read the child's control register and active data segment");
    if (protected_mode) {
        check((sregs.cr0 & 1) && sregs.cs.selector == 8 && sregs.cs.db == !long_mode &&
              sregs.ds.selector == 16 && sregs.ds.base == 0 && sregs.ds.limit == UINT32_MAX &&
              sregs.gdt.base == gpa + GDT_OFFSET && sregs.gdt.limit == 23,
              "observe the client's flat protected-mode state");
        if (long_mode)
            check(sregs.cs.l && (sregs.cr0 & LONG_CR0) == LONG_CR0 && sregs.cr3 == gpa + 4096 &&
                  (sregs.cr4 & LONG_CR4) && (sregs.efer & LONG_EFER) == LONG_EFER,
                  "observe active long-mode paging");
    } else {
        check(sregs.ds.selector == pages * 0x100 && sregs.ds.base == pages * 4096 &&
              sregs.ds.limit == 0xffff && sregs.gdt.base == 0x123480 && sregs.gdt.limit == 0x2f,
              "observe the descriptor table written by the real-mode child");
    }
    check(ram[0x90] == 0x57 && data[0x80] == 0x56 && data[0x82] == 0,
          "child wrote the first and last pages and stopped after its first output");
    check(!protected_mode || middle[0x78] == 0xb3, "protected child wrote the middle page");
    if (cpuid)
        check_cpuid_result(ram, 0, &supported);
    if (mmio)
        check(ram[0xf0] == 3, "resume after the final MMIO write");
    if (mmio_read) {
        uint64_t observed_value;
        memcpy(&observed_value, ram + 0x108, sizeof(observed_value));
        check(observed_value == MMIO_SECOND_VALUE, "continue from the second read with userspace data");
        puts("PASS MMIO reads continued with VMM-supplied bytes");
    }
    if (two_vcpus) {
        check(data[0xa0] == 0 && data[0xa1] == 0, "second vCPU waited for KVM_RUN");
        timed_run(other_cpu);
        check_output(other_run, size, 0x56);
        check_registers(other_cpu, 0x56, 0x3344, gpa + SECOND_CPU_OFFSET);
        check_registers(cpu, 0x42, 0x1357, gpa);
        check(data[0xa0] == 0x56 && data[0xa1] == 0, "second vCPU read shared RAM and stopped at its exit");
        if (cpuid)
            check_cpuid_result(data, 1, &supported);
        check(munmap(other_run, size) == 0 && close(other_cpu) == 0, "close the second vCPU");
    }
    if (fpu)
        update_fpu(cpu, ram);
    if (msrs)
        update_msrs(cpu, ram);
    data[0x81] = 0x52;
    const struct kvm_regs update = {
        .rbx = 0xf5, .rcx = 0x3579, .rsp = 0x1f00, .rbp = 0x12345678,
        .rdi = protected_mode ? data_address : 0, .rip = entry_base + (interrupt_run ? 0x60 : 0x40), .rflags = 2,
    };
    check(ioctl(cpu, KVM_SET_REGS, &update) == 0, "set stopped registers before re-entry");
    check(ioctl(cpu, KVM_GET_REGS, &readback) == 0 && !memcmp(&readback, &update, sizeof(readback)),
          "read back updated registers");
    if (interrupt_run)
        interrupt_and_resume(cpu, data, entry_base);
    unsigned long long second = timed_run(cpu);
    check_output(run, size, 0xa7);
    check_registers(cpu, 0xa7, 0x2468, entry_base);
    check(data[0x82] == 0x52, "child saw the client's write during re-entry");
    if (two_vcpus) {
        check(data[0xa1] == 0, "closing a vCPU leaves it stopped during another vCPU's run");
        puts("PASS two vCPUs kept independent state in one child");
    }
    if (interrupt_run)
        puts("PASS stopped and resumed the same running child");
    if (long_mode)
        puts("PASS x86-64 child used guest page tables and a virtual RAM alias");
    if (fpu)
        check_resumed_fpu(cpu, data);
    if (msrs)
        check_resumed_msrs(cpu, data);
    if (cpuid)
        puts("PASS child CPUID instructions used the installed vCPU profiles");
    if (mmio)
        puts("PASS MMIO writes returned physical addresses and exact data");
    munmap(run, size);
    close(cpu);
    munmap(ram, ram_bytes);
    close(kvm);
    printf("KVM_RUN_NS first=%llu warm=%llu\n", first, second);
    puts("PASS /dev/kvm returned two port I/O exits");
    return 0;
}
