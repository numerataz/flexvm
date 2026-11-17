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
#include <unistd.h>

static void check(bool valid, const char *why)
{
    if (valid) return;
    fprintf(stderr, "FAIL parent KVM: %s: %s\n", why, strerror(errno));
    exit(1);
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
    /* mov byte [0x1010], 0x56; mov al, 0x42; out 0x30, al */
    static const unsigned char code[] = {0xc6, 0x06, 0x10, 0x10, 0x56, 0xb0, 0x42, 0xe6, 0x30};
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
    check(ioctl(cpu, KVM_RUN, 0) == 0, "parent executes L2");
    check(run->exit_reason == KVM_EXIT_IO && run->io.direction == KVM_EXIT_IO_OUT &&
          run->io.size == 1 && run->io.count == 1 && run->io.port == 0x30 &&
          run->io.data_offset < (unsigned)size &&
          ((unsigned char *)run)[run->io.data_offset] == 0x42, "real KVM I/O exit");
    check(ram[0x10] == 0x56, "child write visible in the original mapping");
    munmap(run, size);
    close(cpu);
    munmap(ram, 4096);
    close(kvm);
    puts("PASS /dev/kvm returned the expected port I/O exit");
    return 0;
}
