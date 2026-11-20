#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "mailbox.h"

#define PROTECTED_SLOT_GPA 0x1000000
#define SPLIT_SLOT_GPA 0x20000000
#define GDT_OFFSET 0x200

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

static void check_registers(int cpu, unsigned char accumulator, unsigned int counter, uint64_t gpa)
{
    struct kvm_regs regs;

    check(ioctl(cpu, KVM_GET_REGS, &regs) == 0, "read actual registers after exit");
    check((regs.rax & 0xff) == accumulator && regs.rcx == counter &&
          regs.rip >= gpa && (regs.rflags & 2), "check actual registers after exit");
}

static void select_segments(int cpu, bool protected_mode, uint64_t gpa)
{
    struct kvm_sregs sregs;
    check(ioctl(cpu, KVM_GET_SREGS, &sregs) == 0, "read reset segments");
    if (protected_mode) {
        const struct kvm_segment code = {
            .limit = UINT32_MAX, .selector = 8, .type = 11, .present = 1,
            .db = 1, .s = 1, .g = 1,
        };
        const struct kvm_segment data = {
            .limit = UINT32_MAX, .selector = 16, .type = 3, .present = 1,
            .db = 1, .s = 1, .g = 1,
        };
        sregs.cs = code;
        sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = data;
        sregs.gdt = (struct kvm_dtable){.base = gpa + GDT_OFFSET, .limit = 23};
        sregs.cr0 |= 1;
    } else {
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
    }
    check(ioctl(cpu, KVM_SET_SREGS, &sregs) == 0, "select the child execution mode");
}

int main(int argc, char **argv)
{
    bool split_slot = argc == 3 && !strcmp(argv[2], "split");
    bool protected_mode = split_slot || (argc == 3 && !strcmp(argv[2], "protected"));
    check(argc == 2 || protected_mode, "specify the RAM page count and optional protected or split mode");
    char *end;
    errno = 0;
    long count = strtol(argv[1], &end, 10);
    check(!errno && !*end && count > 0 && count <= PVKVM_MAX_PAGES, "select the RAM page count");
    check(protected_mode || count <= PVKVM_REAL_MODE_MAX_PAGES, "select protected mode for a large slot");
    check(!split_slot || count >= 2, "split mode needs at least two RAM pages");
    size_t pages = count;
    size_t ram_bytes = pages * 4096;
    uint64_t gpa = protected_mode ? PROTECTED_SLOT_GPA : PVKVM_GUEST_START;
    uint64_t middle_page = gpa + (pages / 2) * 4096;
    uint64_t last_page = gpa + ram_bytes - 4096;
    if (split_slot) {
        middle_page = SPLIT_SLOT_GPA;
        last_page = SPLIT_SLOT_GPA + (pages - pages / 2 - 1) * 4096;
    }
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0, "open /dev/kvm");
    check(ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "API version");
    check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY) == 1 &&
          ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_NR_MEMSLOTS) >= PVKVM_MAX_SLOTS,
          "query system KVM memory capabilities");
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
    unsigned char *data = ram + ram_bytes - 4096;
    unsigned char *middle = ram + (pages / 2) * 4096;
    const unsigned char gdtr[] = {0x2f, 0x00, 0x80, 0x34, 0x12, 0x00};
    const uint64_t gdt[] = { 0, 0x00cf9b000000ffff, 0x00cf93000000ffff };
    if (protected_mode) {
        memcpy(ram + 0x10, flat_code, sizeof(flat_code));
        memcpy(ram + 0x40, flat_resumed, sizeof(flat_resumed));
        memcpy(ram + GDT_OFFSET, gdt, sizeof(gdt));
    } else {
        memcpy(ram + 0x10, code, sizeof(code));
        memcpy(ram + 0x40, resumed, sizeof(resumed));
        memcpy(data + 0x100, gdtr, sizeof(gdtr));
    }
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    check(cpu >= 0 && (fcntl(cpu, F_GETFD) & FD_CLOEXEC), "vCPU file descriptor");
    check(ioctl(vm, KVM_CREATE_VCPU, 0) == -1 && errno == EEXIST, "reject duplicate vCPU");
    struct kvm_run *run = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
    check(run != MAP_FAILED, "map kvm_run");
    struct kvm_regs regs = {.rax = 0x41, .rip = gpa + 0x10, .rflags = 3};
    if (protected_mode) {
        regs.rbx = last_page;
        regs.rdi = gpa;
        regs.rsi = middle_page;
    }
    check(ioctl(cpu, KVM_SET_REGS, &regs) == 0, "set initial registers");
    struct kvm_regs readback;
    check(ioctl(cpu, KVM_GET_REGS, &readback) == 0 && !memcmp(&readback, &regs, sizeof(regs)),
          "read back initial registers");
    select_segments(cpu, protected_mode, gpa);
    close(vm);
    run->immediate_exit = 1;
    check(ioctl(cpu, KVM_RUN, 0) == -1 && errno == EINTR, "immediate exit");
    run->immediate_exit = 0;
    unsigned long long first = timed_run(cpu);
    check_output(run, size, 0x42);
    check_registers(cpu, 0x42, 0x1357, gpa);
    struct kvm_sregs sregs;
    check(ioctl(cpu, KVM_GET_SREGS, &sregs) == 0, "read actual special registers after exit");
    check(sregs.cr2 == 0x89abcdef && sregs.ds.present && !sregs.ds.unusable,
          "read the child's control register and active data segment");
    if (protected_mode) {
        check((sregs.cr0 & 1) && sregs.cs.selector == 8 && sregs.cs.db &&
              sregs.ds.selector == 16 && sregs.ds.base == 0 && sregs.ds.limit == UINT32_MAX &&
              sregs.gdt.base == gpa + GDT_OFFSET && sregs.gdt.limit == 23,
              "observe the client's flat protected-mode state");
    } else {
        check(sregs.ds.selector == pages * 0x100 && sregs.ds.base == pages * 4096 &&
              sregs.ds.limit == 0xffff && sregs.gdt.base == 0x123480 && sregs.gdt.limit == 0x2f,
              "observe the descriptor table written by the real-mode child");
    }
    check(ram[0x90] == 0x57 && data[0x80] == 0x56 && data[0x82] == 0,
          "child wrote the first and last pages and stopped after its first output");
    check(!protected_mode || middle[0x78] == 0xb3, "protected child wrote the middle page");
    data[0x81] = 0x52;
    const struct kvm_regs update = {
        .rbx = 0xf5, .rcx = 0x3579, .rsp = 0x1f00, .rbp = 0x12345678,
        .rdi = protected_mode ? last_page : 0, .rip = gpa + 0x40, .rflags = 2,
    };
    check(ioctl(cpu, KVM_SET_REGS, &update) == 0, "set stopped registers before re-entry");
    check(ioctl(cpu, KVM_GET_REGS, &readback) == 0 && !memcmp(&readback, &update, sizeof(readback)),
          "read back updated registers");
    unsigned long long second = timed_run(cpu);
    check_output(run, size, 0xa7);
    check_registers(cpu, 0xa7, 0x2468, gpa);
    check(data[0x82] == 0x52, "child saw the client's write during re-entry");
    munmap(run, size);
    close(cpu);
    munmap(ram, ram_bytes);
    close(kvm);
    printf("KVM_RUN_NS first=%llu warm=%llu\n", first, second);
    puts("PASS /dev/kvm returned two port I/O exits");
    return 0;
}
