/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void check(int ok, const char *why)
{
    if (ok) return;
    perror(why);
    reboot(RB_POWER_OFF);
    _exit(1);
}

#ifdef FLEXVM_ARM_INITIAL_STATE_TEST
static void check_initial_state(int vm)
{
    struct kvm_vcpu_init init = {};
    check(ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init) == 0, "ARM preferred target");
    init.features[0] |= 1U << KVM_ARM_VCPU_PSCI_0_2;
    int boot = ioctl(vm, KVM_CREATE_VCPU, 0);
    check(boot >= 0, "open boot ARM vCPU");
    check(ioctl(boot, KVM_ARM_VCPU_INIT, &init) == 0, "initialize boot ARM vCPU");
    int secondary = ioctl(vm, KVM_CREATE_VCPU, 1);
    check(secondary >= 0, "open uninitialized secondary ARM vCPU");
    const uint64_t canary = 0x539abf42c7de6135ULL;
    uint64_t value = canary;
    struct kvm_one_reg reg = {
        .id = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE |
              (offsetof(struct kvm_regs, regs.regs[0]) / sizeof(uint32_t)),
        .addr = (uintptr_t)&value,
    };
    check(ioctl(boot, KVM_SET_ONE_REG, &reg) == 0, "stage ARM boot register");
    struct kvm_mp_state mp = { .mp_state = KVM_MP_STATE_STOPPED };
    check(ioctl(boot, KVM_SET_MP_STATE, &mp) == 0, "stage ARM boot power state");
    puts("ARM checkpoint window before first KVM_RUN");
    struct timespec wait = { .tv_sec = 4 };
    while (nanosleep(&wait, &wait) == -1)
        check(errno == EINTR, "wait for ARM pre-run checkpoint");
    value = 0;
    check(ioctl(boot, KVM_GET_ONE_REG, &reg) == 0 && value == canary, "restore staged ARM boot register");
    mp.mp_state = UINT32_MAX;
    check(ioctl(boot, KVM_GET_MP_STATE, &mp) == 0 && mp.mp_state == KVM_MP_STATE_STOPPED, "restore staged ARM boot power state");
    check(ioctl(secondary, KVM_GET_ONE_REG, &reg) == -1 && errno == ENOEXEC, "secondary ARM vCPU remains uninitialized");
    check(close(secondary) == 0 && close(boot) == 0, "close pre-run ARM vCPUs");
    puts("PASS ARM pending vCPU configuration survived checkpoint");
}
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    check(mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) == 0, "devtmpfs");
    check(access("/dev/kvm", F_OK) == -1 && errno == ENOENT, "exclusive ARM provider");
    int module = open("/flexvm-pvkvm.ko", O_RDONLY | O_CLOEXEC);
    check(module >= 0 && syscall(SYS_finit_module, module, "", 0) == 0, "load ARM parent KVM module");
    close(module);
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0, "open ARM parent KVM device");
    check(ioctl(kvm, KVM_GET_API_VERSION, 0) == 12, "ARM KVM version");
    int ipa_bits = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
    check(ipa_bits >= 32 && ipa_bits <= 52, "negotiated ARM IPA");
    check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ONE_REG) == 1, "ARM register support");
    check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ARM_PSCI_0_2) == 1, "ARM PSCI capability");
    check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_SET_TSS_ADDR) == 0, "ARM capability selection");
    check(ioctl(kvm, KVM_CREATE_VM, 31) == -1 && errno == EINVAL, "invalid ARM VM type");
    int vm = ioctl(kvm, KVM_CREATE_VM, ipa_bits);
    check(vm >= 0, "open ARM parent VM");
    check(ioctl(kvm, KVM_CREATE_VM, ipa_bits) == -1 && errno == EBUSY, "ARM parent single VM admission");
#ifdef FLEXVM_ARM_INITIAL_STATE_TEST
    check_initial_state(vm);
#endif
    check(close(vm) == 0, "close ARM parent VM");
    close(kvm);
    puts("PASS ARM parent KVM frontend loaded and negotiated Linux ABI");
#ifdef FLEXVM_ARM_NATIVE_TEST
    pid_t child = fork();
    check(child >= 0, "fork ARM KVM ABI client");
    if (!child) {
        execl("/kvm-abi", "kvm-abi", NULL);
        _exit(127);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "ARM KVM ABI client");
    puts("PASS ARM parent-owned KVM device ran the unmodified ABI client");
#endif
    reboot(RB_POWER_OFF);
    return 0;
}
