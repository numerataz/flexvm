#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kvm.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

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
    check(argc == 4 || argc == 5, "expected control fd, outer RAM fd, and one or two page offsets");
    int control = (int)number(argv[1], INT_MAX);
    int outer_ram = (int)number(argv[2], INT_MAX);
    size_t slot_bytes = (size_t)(argc - 3) * 4096;
    unsigned char *slot = mmap(NULL, slot_bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(slot != MAP_FAILED, "reserve a contiguous address range for guest RAM");
    for (int arg = 3; arg < argc; arg++) {
        off_t offset = (off_t)number(argv[arg], LONG_MAX);
        check(offset % 4096 == 0, "unaligned outer RAM offset");
        void *address = slot + (arg - 3) * 4096;
        check(mmap(address, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                   outer_ram, offset) == address, "map outer RAM page");
    }

    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION,
          "open a compatible host KVM device");
    int bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    check(bytes >= (int)sizeof(struct kvm_run), "KVM run mapping size");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0, "create host VM");
    struct kvm_userspace_memory_region memory = {
        .guest_phys_addr = 4096, .memory_size = slot_bytes, .userspace_addr = (uintptr_t)slot,
    };
    check(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &memory) == 0, "register shared page");
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    check(cpu >= 0, "create host vCPU");
    struct kvm_run *run = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
    check(run != MAP_FAILED, "map host kvm_run");
    struct kvm_sregs segments;
    check(ioctl(cpu, KVM_GET_SREGS, &segments) == 0, "read reset segments");
    segments.cs.base = 0;
    segments.cs.selector = 0;
    check(ioctl(cpu, KVM_SET_SREGS, &segments) == 0, "select real-mode code segment");
    struct kvm_regs registers = {.rip = 4096, .rflags = 2};
    check(ioctl(cpu, KVM_SET_REGS, &registers) == 0, "set host entry registers");

    check(write(control, "R", 1) == 1, "announce worker readiness");
    unsigned char request[2];
    ssize_t received;
    while ((received = read(control, request, sizeof(request))) != 0) {
        if (received < 0 && errno == EINTR) continue;
        if (received == 1 && request[0] == 'G') {
            check(ioctl(cpu, KVM_GET_REGS, &registers) == 0, "read host registers after exit");
            check(write(control, &registers, sizeof(registers)) == (ssize_t)sizeof(registers),
                  "return host registers to the parent");
            continue;
        }
        check(received == 1 && request[0] == 'R', "invalid run request");
        check(ioctl(cpu, KVM_RUN, 0) == 0, "run host vCPU");
        check(run->exit_reason == KVM_EXIT_IO && run->io.direction == KVM_EXIT_IO_OUT &&
              run->io.port == 0x30 && run->io.count == 1 && run->io.size == 1 &&
              run->io.data_offset < (unsigned long)bytes, "unexpected host vCPU exit");
        unsigned char value = ((unsigned char *)run)[run->io.data_offset];
        check(write(control, &value, 1) == 1, "reply to the parent");
    }
    return 0;
}
