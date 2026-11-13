// KVM ABI reference checks. The same binary will test FlexVM's compatibility provider.
// cc -std=c11 -O2 -Wall -Wextra -Werror -static kvm-abi.c -o kvm-abi
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error These execution checks currently target the x86 KVM ABI.
#endif

#define RAM_SIZE 0x10000
#define CODE_ADDR 0x1000
#define DATA_ADDR 0x2000
#define IO_PORT 0x3f8
#define REQUIRE(test) do { if (!(test)) { \
    fprintf(stderr, "FAIL line %d: %s (errno %d: %s)\n", __LINE__, #test, errno, strerror(errno)); \
    exit(1); \
} } while (0)

static unsigned passed;
static void pass(const char *name) { printf("PASS: %s\n", name); passed++; }
static void expired(int sig) {
    (void)sig;
    const char message[] = "FAIL: KVM ABI execution timed out\n";
    ssize_t ignored = write(STDERR_FILENO, message, sizeof(message) - 1);
    (void)ignored;
    _exit(1);
}

struct machine {
    int vm, cpu;
    uint8_t *ram;
    struct kvm_run *run;
    size_t run_size;
};

static uint8_t *memory(uint8_t value) {
    uint8_t *ram = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ram != MAP_FAILED);
    // Real mode: load caller-owned RAM, output a byte, increment that same RAM, halt.
    const uint8_t code[] = {0xbb, 0x00, 0x20, 0xba, 0xf8, 0x03, 0x8a, 0x07, 0xee, 0xfe, 0x07, 0xf4};
    memcpy(ram + CODE_ADDR, code, sizeof(code));
    ram[DATA_ADDR] = value;
    return ram;
}

static void region(struct machine *m, uint8_t *ram, size_t size) {
    struct kvm_userspace_memory_region slot = {
        .slot = 0, .guest_phys_addr = 0, .memory_size = size,
        .userspace_addr = (uintptr_t)ram,
    };
    REQUIRE(ioctl(m->vm, KVM_SET_USER_MEMORY_REGION, &slot) == 0);
}

static void reset_cpu(struct machine *m) {
    struct kvm_sregs sregs;
    REQUIRE(ioctl(m->cpu, KVM_GET_SREGS, &sregs) == 0);
    sregs.cs.base = sregs.ds.base = sregs.es.base = sregs.ss.base = 0;
    sregs.cs.selector = sregs.ds.selector = sregs.es.selector = sregs.ss.selector = 0;
    REQUIRE(ioctl(m->cpu, KVM_SET_SREGS, &sregs) == 0);
    struct kvm_regs regs = {.rip = CODE_ADDR, .rsp = 0x8000, .rflags = 2};
    REQUIRE(ioctl(m->cpu, KVM_SET_REGS, &regs) == 0);
    struct kvm_mp_state mp = {.mp_state = KVM_MP_STATE_RUNNABLE};
    REQUIRE(ioctl(m->cpu, KVM_SET_MP_STATE, &mp) == 0);
}

static struct machine create(int kvm, const struct kvm_cpuid2 *cpuid, uint8_t value) {
    struct machine m = {.vm = -1, .cpu = -1};
    m.vm = ioctl(kvm, KVM_CREATE_VM, 0);
    REQUIRE(m.vm >= 0);
    m.ram = memory(value);
    region(&m, m.ram, RAM_SIZE);
    m.cpu = ioctl(m.vm, KVM_CREATE_VCPU, 0);
    REQUIRE(m.cpu >= 0);
    REQUIRE(ioctl(m.cpu, KVM_SET_CPUID2, cpuid) == 0);
    int size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    REQUIRE(size >= (int)sizeof(struct kvm_run));
    m.run_size = (size_t)size;
    m.run = mmap(NULL, m.run_size, PROT_READ | PROT_WRITE, MAP_SHARED, m.cpu, 0);
    REQUIRE(m.run != MAP_FAILED);
    reset_cpu(&m);
    return m;
}

static void destroy(struct machine *m) {
    REQUIRE(munmap(m->run, m->run_size) == 0);
    REQUIRE(close(m->cpu) == 0);
    if (m->vm >= 0) REQUIRE(close(m->vm) == 0);
    REQUIRE(munmap(m->ram, RAM_SIZE) == 0);
}

static void run(struct machine *m, uint32_t expected) {
    alarm(10);
    int result;
    do { result = ioctl(m->cpu, KVM_RUN, 0); } while (result < 0 && errno == EINTR);
    alarm(0);
    REQUIRE(result == 0);
    if (m->run->exit_reason != expected) {
        fprintf(stderr, "unexpected KVM exit %u (expected %u)\n", m->run->exit_reason, expected);
        exit(1);
    }
}

static void output(struct machine *m, uint8_t expected) {
    run(m, KVM_EXIT_IO);
    REQUIRE(m->run->io.direction == KVM_EXIT_IO_OUT);
    REQUIRE(m->run->io.port == IO_PORT && m->run->io.size == 1 && m->run->io.count == 1);
    REQUIRE(m->run->io.data_offset < m->run_size);
    REQUIRE(*((uint8_t *)m->run + m->run->io.data_offset) == expected);
}

int main(int argc, char **argv) {
    REQUIRE(argc <= 2);
    signal(SIGALRM, expired);
    const char *path = argc == 2 ? argv[1] : "/dev/kvm";
    int kvm = open(path, O_RDWR | O_CLOEXEC);
    if (kvm < 0) {
        fprintf(stderr, "Cannot open KVM ABI provider %s: %s\n", path, strerror(errno));
        return 1; // Required test: an unavailable provider is a failure, never a skip.
    }
    REQUIRE(ioctl(kvm, KVM_GET_API_VERSION, 0) == 12);
    REQUIRE(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY) > 0);
    REQUIRE(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_IOEVENTFD) > 0);
    REQUIRE(ioctl(kvm, KVM_CHECK_EXTENSION, 0x7fffffff) == 0);
    pass("API version and honest capability discovery");

    const unsigned max_cpuid = 256;
    struct kvm_cpuid2 *cpuid = calloc(1, sizeof(*cpuid) + max_cpuid * sizeof(struct kvm_cpuid_entry2));
    REQUIRE(cpuid != NULL);
    cpuid->nent = max_cpuid;
    REQUIRE(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid) == 0);
    REQUIRE(cpuid->nent > 0 && cpuid->nent <= max_cpuid);
    pass("supported CPU configuration");

    struct machine a = create(kvm, cpuid, 0x41);
    struct machine b = create(kvm, cpuid, 0x61);
    output(&a, 0x41);
    // The stopped vCPU must see a caller write immediately when it resumes.
    a.ram[DATA_ADDR] = 0x50;
    run(&a, KVM_EXIT_HLT);
    REQUIRE(a.ram[DATA_ADDR] == 0x51);
    pass("vCPU IO/run-page ABI and coherent caller-owned RAM");
    output(&b, 0x61);
    run(&b, KVM_EXIT_HLT);
    REQUIRE(b.ram[DATA_ADDR] == 0x62 && a.ram[DATA_ADDR] == 0x51);
    pass("independent VM descriptor and RAM state");

    struct kvm_regs saved, changed, restored;
    REQUIRE(ioctl(a.cpu, KVM_GET_REGS, &saved) == 0);
    changed = saved;
    changed.rax = UINT64_C(0x123456789abcdef);
    REQUIRE(ioctl(a.cpu, KVM_SET_REGS, &changed) == 0);
    REQUIRE(ioctl(a.cpu, KVM_GET_REGS, &restored) == 0);
    REQUIRE(restored.rax == changed.rax);
    REQUIRE(ioctl(a.cpu, KVM_SET_REGS, &saved) == 0);
    pass("vCPU register state round trip");

    uint8_t *replacement = memory(0x71);
    struct kvm_userspace_memory_region changed_slot = {
        .slot = 0, .guest_phys_addr = 0, .memory_size = RAM_SIZE,
        .userspace_addr = (uintptr_t)replacement,
    };
    errno = 0;
    REQUIRE(ioctl(a.vm, KVM_SET_USER_MEMORY_REGION, &changed_slot) == -1 && errno == EINVAL);
    // A rejected change must leave the previous mapping intact.
    reset_cpu(&a);
    output(&a, 0x51);
    run(&a, KVM_EXIT_HLT);
    REQUIRE(a.ram[DATA_ADDR] == 0x52);
    uint8_t *old = a.ram;
    region(&a, old, 0);
    a.ram = replacement;
    region(&a, a.ram, RAM_SIZE);
    REQUIRE(munmap(old, RAM_SIZE) == 0);
    reset_cpu(&a);
    output(&a, 0x71);
    run(&a, KVM_EXIT_HLT);
    REQUIRE(a.ram[DATA_ADDR] == 0x72);
    region(&a, a.ram, 0);
    region(&a, a.ram, RAM_SIZE);
    pass("rejected in-place address change and explicit memory slot re-registration");

    int event = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    REQUIRE(event >= 0);
    struct kvm_ioeventfd io = {
        .datamatch = 0x41, .addr = IO_PORT, .len = 1, .fd = event,
        .flags = KVM_IOEVENTFD_FLAG_DATAMATCH | KVM_IOEVENTFD_FLAG_PIO,
    };
    REQUIRE(ioctl(a.vm, KVM_IOEVENTFD, &io) == 0);
    a.ram[DATA_ADDR] = 0x41;
    reset_cpu(&a);
    run(&a, KVM_EXIT_HLT);
    uint64_t count;
    REQUIRE(read(event, &count, sizeof(count)) == sizeof(count) && count == 1);
    io.flags |= KVM_IOEVENTFD_FLAG_DEASSIGN;
    REQUIRE(ioctl(a.vm, KVM_IOEVENTFD, &io) == 0);
    REQUIRE(close(event) == 0);
    reset_cpu(&a);
    output(&a, 0x42);
    pass("ioeventfd delivery, deassignment and userspace IO fallback");

    REQUIRE(close(b.vm) == 0);
    b.vm = -1;
    reset_cpu(&b);
    output(&b, 0x62);
    run(&b, KVM_EXIT_HLT);
    REQUIRE(b.ram[DATA_ADDR] == 0x63);
    pass("vCPU descriptor keeps VM alive after VM descriptor closes");
    destroy(&a);
    destroy(&b);
    REQUIRE(close(kvm) == 0);
    free(cpuid);
    printf("PASS: %u KVM ABI reference checks\n", passed);
    return 0;
}
