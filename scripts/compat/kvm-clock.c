// Correlated fallback KVM clock data, independent of a TSC master clock.
#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define SECOND UINT64_C(1000000000)
#define REQUIRE(test) do { if (!(test)) { fprintf(stderr, "KVM clock check failed at line %d: %s\n", __LINE__, #test); exit(1); } } while (0)
static uint64_t realtime(void) {
    struct timespec now;
    REQUIRE(clock_gettime(CLOCK_REALTIME, &now) == 0);
    return (uint64_t)now.tv_sec * SECOND + (uint64_t)now.tv_nsec;
}
static struct kvm_clock_data sample(int vm) {
    struct kvm_clock_data data = {0};
    uint64_t before = realtime();
    REQUIRE(ioctl(vm, KVM_GET_CLOCK, &data) == 0);
    uint64_t after = realtime();
    printf("KVM_CLOCK flags=%u clock=%" PRIu64 " realtime=%" PRIu64 " before=%" PRIu64 " after=%" PRIu64 "\n",
           data.flags, (uint64_t)data.clock, (uint64_t)data.realtime, before, after);
    REQUIRE(data.flags & KVM_CLOCK_REALTIME);
    // A VM without vCPUs cannot use the matched-vCPU master TSC path.
    REQUIRE(!(data.flags & (KVM_CLOCK_TSC_STABLE | KVM_CLOCK_HOST_TSC)));
    REQUIRE(data.realtime >= before && data.realtime <= after);
    return data;
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    REQUIRE(kvm >= 0);
    REQUIRE(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ADJUST_CLOCK) & KVM_CLOCK_REALTIME);
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    REQUIRE(vm >= 0);
    struct kvm_clock_data saved = sample(vm);
    REQUIRE(saved.realtime >= SECOND);
    saved.clock = SECOND;
    saved.realtime -= SECOND;
    saved.flags = KVM_CLOCK_REALTIME;
    REQUIRE(ioctl(vm, KVM_SET_CLOCK, &saved) == 0);
    struct kvm_clock_data restored = sample(vm);
    REQUIRE(restored.clock >= 2 * SECOND);
    REQUIRE(close(vm) == 0 && close(kvm) == 0);
    puts("FLEXVM_SOFTWARE_GUEST_CLOCK_PASSED");
    return 0;
}
