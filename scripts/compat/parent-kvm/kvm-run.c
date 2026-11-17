#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "mailbox.h"

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

static void check_registers(int cpu, unsigned char accumulator, unsigned int counter)
{
    struct kvm_regs regs;

    check(ioctl(cpu, KVM_GET_REGS, &regs) == 0, "read actual registers after exit");
    check((regs.rax & 0xff) == accumulator && regs.rcx == counter &&
          regs.rip >= 4096 && (regs.rflags & 2), "check actual registers after exit");
}

int main(int argc, char **argv)
{
    check(argc == 2, "specify the RAM page count");
    char *end;
    errno = 0;
    long count = strtol(argv[1], &end, 10);
    check(!errno && !*end && count > 0 && count <= PVKVM_MAX_PAGES, "select the RAM page count");
    size_t pages = count;
    size_t ram_bytes = pages * 4096;
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0, "open /dev/kvm");
    check(ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "API version");
    int size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    check(size >= (int)sizeof(struct kvm_run), "run mapping size");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0 && (fcntl(vm, F_GETFD) & FD_CLOEXEC), "VM file descriptor");
    unsigned char *ram = mmap(NULL, ram_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(ram != MAP_FAILED, "map client RAM");
    volatile unsigned char *scratch = NULL;
    size_t gap = 32 * 4096;
    size_t scratch_bytes = (pages - 1) * gap;
    if (scratch_bytes) {
        volatile unsigned char *touch = ram;
        scratch = mmap(NULL, scratch_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        check(scratch != MAP_FAILED, "allocate intervening pages");
        for (size_t page = pages - 1; page; page--) {
            touch[page * 4096] = 0;
            for (size_t byte = (page - 1) * gap; byte < page * gap; byte += 4096)
                scratch[byte] = 1;
        }
        touch[0] = 0;
    }
    struct kvm_userspace_memory_region region = {
        .guest_phys_addr = 4096, .memory_size = ram_bytes, .userspace_addr = (unsigned long)ram,
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
    memcpy(ram + 0x10, code, sizeof(code));
    memcpy(ram + 0x40, resumed, sizeof(resumed));
    unsigned char *data = ram + ram_bytes - 4096;
    const unsigned char gdtr[] = {0x2f, 0x00, 0x80, 0x34, 0x12, 0x00};
    memcpy(data + 0x100, gdtr, sizeof(gdtr));
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    check(cpu >= 0 && (fcntl(cpu, F_GETFD) & FD_CLOEXEC), "vCPU file descriptor");
    check(ioctl(vm, KVM_CREATE_VCPU, 0) == -1 && errno == EEXIST, "reject duplicate vCPU");
    struct kvm_run *run = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
    check(run != MAP_FAILED, "map kvm_run");
    struct kvm_sregs sregs;
    check(ioctl(cpu, KVM_GET_SREGS, &sregs) == 0, "read reset segments");
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    check(ioctl(cpu, KVM_SET_SREGS, &sregs) == 0, "select real-mode code segment");
    struct kvm_regs regs = {.rax = 0x41, .rip = 0x1010, .rflags = 3};
    check(ioctl(cpu, KVM_SET_REGS, &regs) == 0, "set initial registers");
    struct kvm_regs readback;
    check(ioctl(cpu, KVM_GET_REGS, &readback) == 0 && !memcmp(&readback, &regs, sizeof(regs)),
          "read back initial registers");
    close(vm);
    run->immediate_exit = 1;
    check(ioctl(cpu, KVM_RUN, 0) == -1 && errno == EINTR, "immediate exit");
    run->immediate_exit = 0;
    unsigned long long first = timed_run(cpu);
    check_output(run, size, 0x42);
    check_registers(cpu, 0x42, 0x1357);
    check(ioctl(cpu, KVM_GET_SREGS, &sregs) == 0, "read actual special registers after exit");
    check(sregs.ds.selector == pages * 0x100 && sregs.ds.base == pages * 4096 &&
          sregs.ds.limit == 0xffff && sregs.ds.present && !sregs.ds.unusable &&
          sregs.gdt.base == 0x123480 && sregs.gdt.limit == 0x2f && sregs.cr2 == 0x89abcdef,
          "observed segment cache, descriptor table, and control register match child instructions");
    check(ram[0x90] == 0x57 && data[0x80] == 0x56 && data[0x82] == 0,
          "child wrote the first and last slots and stopped after its first output");
    data[0x81] = 0x52;
    const struct kvm_regs update = {
        .rbx = 0xf5, .rcx = 0x3579, .rsp = 0x1f00, .rbp = 0x12345678,
        .rip = 0x1040, .rflags = 2,
    };
    check(ioctl(cpu, KVM_SET_REGS, &update) == 0, "set stopped registers before re-entry");
    check(ioctl(cpu, KVM_GET_REGS, &readback) == 0 && !memcmp(&readback, &update, sizeof(readback)),
          "read back updated registers");
    unsigned long long second = timed_run(cpu);
    check_output(run, size, 0xa7);
    check_registers(cpu, 0xa7, 0x2468);
    check(data[0x82] == 0x52, "child saw the client's write during re-entry");
    munmap(run, size);
    close(cpu);
    munmap(ram, ram_bytes);
    close(kvm);
    printf("KVM_RUN_NS first=%llu warm=%llu\n", first, second);
    puts("PASS /dev/kvm returned two port I/O exits");
    return 0;
}
