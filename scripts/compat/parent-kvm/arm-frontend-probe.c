/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <unistd.h>

static void check(int ok, const char *why)
{
    if (ok) return;
    perror(why);
    reboot(RB_POWER_OFF);
    _exit(1);
}

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
    check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE) == 48, "negotiated ARM IPA");
    check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ONE_REG) == 1, "ARM register support");
    check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ARM_PSCI_0_2) == 1, "ARM PSCI capability");
    check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_SET_TSS_ADDR) == 0, "ARM capability selection");
    check(ioctl(kvm, KVM_CREATE_VM, 31) == -1 && errno == EINVAL, "invalid ARM VM type");
    int vm = ioctl(kvm, KVM_CREATE_VM, 48);
    check(vm >= 0, "open ARM parent VM");
    check(ioctl(kvm, KVM_CREATE_VM, 48) == -1 && errno == EBUSY, "ARM parent single VM admission");
    check(close(vm) == 0, "close ARM parent VM");
    close(kvm);
    puts("PASS ARM parent KVM frontend loaded and negotiated Linux ABI");
    reboot(RB_POWER_OFF);
    return 0;
}
