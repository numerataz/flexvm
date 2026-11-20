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

int main(void)
{
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0, "open /dev/kvm");
    check(ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "API version");
    int size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    check(size >= (int)sizeof(struct kvm_run), "run mapping size");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0 && (fcntl(vm, F_GETFD) & FD_CLOEXEC), "VM file descriptor");
    unsigned char *ram = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(ram != MAP_FAILED, "map client RAM");
    struct kvm_userspace_memory_region region = {
        .guest_phys_addr = 4096, .memory_size = 4096, .userspace_addr = (unsigned long)ram,
    };
    check(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0, "register client RAM");
    static const unsigned char code[] = {
        0xc6, 0x06, 0x20, 0x10, 0x56, /* mov byte [0x1020], 0x56 */
        0xb0, 0x42, 0xe6, 0x30,       /* mov al, 0x42; out 0x30, al */
        0xa0, 0x21, 0x10,             /* mov al, [0x1021] */
        0xa2, 0x22, 0x10,             /* mov [0x1022], al */
        0xe6, 0x30, 0xf4,             /* out 0x30, al; hlt */
    };
    memcpy(ram, code, sizeof(code));
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
    struct kvm_regs regs = {.rip = 4096, .rflags = 2};
    check(ioctl(cpu, KVM_SET_REGS, &regs) == 0, "set initial registers");
    close(vm);
    run->immediate_exit = 1;
    check(ioctl(cpu, KVM_RUN, 0) == -1 && errno == EINTR, "immediate exit");
    run->immediate_exit = 0;
    unsigned long long first = timed_run(cpu);
    check_output(run, size, 0x42);
    check(ram[0x20] == 0x56 && ram[0x22] == 0, "child stopped after its first output");
    ram[0x21] = 0xa7;
    unsigned long long second = timed_run(cpu);
    check_output(run, size, 0xa7);
    check(ram[0x22] == 0xa7, "child saw the client's write during re-entry");
    munmap(run, size);
    close(cpu);
    munmap(ram, 4096);
    close(kvm);
    printf("KVM_RUN_NS first=%llu warm=%llu\n", first, second);
    puts("PASS /dev/kvm returned two port I/O exits");
    return 0;
}
