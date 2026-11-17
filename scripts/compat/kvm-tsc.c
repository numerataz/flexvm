// Force both unsupported initial TSC frequency paths under emulated SVM.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(test) do { if (!(test)) { \
    fprintf(stderr, "FAIL line %d: %s (errno %d)\n", __LINE__, #test, errno); \
    exit(1); \
} } while (0)

static uint64_t read_tsc(int cpu) {
    struct {
        struct kvm_msrs header;
        struct kvm_msr_entry entry;
    } msrs = {.header.nmsrs = 1, .entry.index = 0x10}; // MSR_IA32_TSC
    REQUIRE(ioctl(cpu, KVM_GET_MSRS, &msrs) == 1);
    return msrs.entry.data;
}

static void initial_rate(int kvm, int numerator, int denominator) {
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    REQUIRE(vm >= 0);
    int native = ioctl(vm, KVM_GET_TSC_KHZ, 0);
    REQUIRE(native > 1 && native < INT32_MAX / 2);
    unsigned long requested = (unsigned long)native * numerator / denominator;
    // Linux 6.1 accepts the VM default even without hardware TSC scaling.
    // A lower rate fails during creation; a higher rate selects catchup.
    REQUIRE(ioctl(vm, KVM_SET_TSC_KHZ, requested) == 0);
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    REQUIRE(cpu >= 0);
    uint64_t before = read_tsc(cpu);
    struct timespec wait = {.tv_nsec = 10000000};
    REQUIRE(nanosleep(&wait, NULL) == 0);
    uint64_t after = read_tsc(cpu);
    printf("TSC initialization: native=%d requested=%lu before=%llu after=%llu\n",
           native, requested, (unsigned long long)before, (unsigned long long)after);
    REQUIRE(before > 0 && after > before);
    // Preserve the existing vCPU ioctl: lower is rejected, higher uses catchup.
    errno = 0;
    if (numerator < denominator) {
        REQUIRE(ioctl(cpu, KVM_SET_TSC_KHZ, requested) == -1 && errno == EINVAL);
    } else {
        REQUIRE(ioctl(cpu, KVM_SET_TSC_KHZ, requested) == 0);
    }
    REQUIRE(read_tsc(cpu) > after);
    REQUIRE(close(cpu) == 0);
    REQUIRE(close(vm) == 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    REQUIRE(kvm >= 0);
    REQUIRE(ioctl(kvm, KVM_GET_API_VERSION, 0) == 12);
    REQUIRE(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_TSC_CONTROL) == 0);
    initial_rate(kvm, 1, 2);
    initial_rate(kvm, 2, 1);
    REQUIRE(close(kvm) == 0);
    puts("PASS: unsupported initial TSC rates retain a running clock");
    return 0;
}
