// Run a minimal ARM64 vCPU through the normal Linux KVM ABI, including under TCG EL2.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error This check targets the ARM64 KVM ABI.
#endif

#define REQUIRE(test) do { if (!(test)) { \
    fprintf(stderr, "FAIL line %d: %s (errno %d: %s)\n", __LINE__, #test, errno, strerror(errno)); \
    exit(1); \
} } while (0)

static void expired(int sig) {
    (void)sig;
    const char message[] = "FAIL: ARM KVM execution timed out\n";
    ssize_t ignored = write(STDERR_FILENO, message, sizeof(message) - 1);
    (void)ignored;
    _exit(1);
}

static void set_core(int cpu, size_t offset, uint64_t value) {
    struct kvm_one_reg reg = {
        .id = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (offset / sizeof(uint32_t)),
        .addr = (uintptr_t)&value,
    };
    REQUIRE(ioctl(cpu, KVM_SET_ONE_REG, &reg) == 0);
}

static void run(int cpu) {
    alarm(15);
    int result;
    do { result = ioctl(cpu, KVM_RUN, 0); } while (result < 0 && errno == EINTR);
    alarm(0);
    REQUIRE(result == 0);
}

int main(void) {
    signal(SIGALRM, expired);
    setvbuf(stdout, NULL, _IONBF, 0);
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    REQUIRE(kvm >= 0);
    REQUIRE(ioctl(kvm, KVM_GET_API_VERSION, 0) == 12);
    REQUIRE(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ONE_REG) > 0);
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    REQUIRE(vm >= 0);
    struct kvm_vcpu_init init = {0};
    REQUIRE(ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init) == 0);
    init.features[0] |= 1U << KVM_ARM_VCPU_PSCI_0_2;
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    REQUIRE(cpu >= 0);
    REQUIRE(ioctl(cpu, KVM_ARM_VCPU_INIT, &init) == 0);

    const size_t size = 0x10000;
    uint32_t *ram = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ram != MAP_FAILED);
    const uint32_t code[] = {
        0x528009a1, // movz w1, #0x4d
        0xb9000001, // str w1, [x0]: deliberate userspace MMIO exit
        0xd2800100, // movz x0, #8
        0xf2b08000, // movk x0, #0x8400, lsl #16: PSCI SYSTEM_OFF
        0xd4000002, // hvc #0
    };
    memcpy(ram, code, sizeof(code));
    struct kvm_userspace_memory_region region = {
        .slot = 0, .guest_phys_addr = 0x40000000, .memory_size = size,
        .userspace_addr = (uintptr_t)ram,
    };
    REQUIRE(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0);
    set_core(cpu, offsetof(struct kvm_regs, regs.pc), 0x40000000);
    set_core(cpu, offsetof(struct kvm_regs, regs.pstate), 0x3c5); // EL1h, interrupts masked
    set_core(cpu, offsetof(struct kvm_regs, regs.regs[0]), 0x10000000);
    int run_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    REQUIRE(run_size >= (int)sizeof(struct kvm_run));
    struct kvm_run *state = mmap(NULL, (size_t)run_size, PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
    REQUIRE(state != MAP_FAILED);
    run(cpu);
    REQUIRE(state->exit_reason == KVM_EXIT_MMIO);
    REQUIRE(state->mmio.is_write == 1 && state->mmio.len == 4 && state->mmio.phys_addr == 0x10000000);
    uint32_t value;
    memcpy(&value, state->mmio.data, sizeof(value));
    REQUIRE(value == 0x4d);
    puts("PASS: ARM KVM vCPU executes and returns a correct MMIO exit");
    run(cpu);
    REQUIRE(state->exit_reason == KVM_EXIT_SYSTEM_EVENT);
    REQUIRE(state->system_event.type == KVM_SYSTEM_EVENT_SHUTDOWN);
    puts("PASS: ARM KVM PSCI shutdown reaches userspace");
    REQUIRE(munmap(state, (size_t)run_size) == 0);
    REQUIRE(munmap(ram, size) == 0);
    REQUIRE(close(cpu) == 0 && close(vm) == 0 && close(kvm) == 0);
    puts("FLEXVM_SOFTWARE_GUEST_KVM_PASSED");
    return 0;
}
