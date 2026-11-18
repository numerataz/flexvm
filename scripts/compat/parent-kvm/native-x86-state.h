/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLEXVM_NATIVE_X86_STATE_H
#define FLEXVM_NATIVE_X86_STATE_H

#include <sys/stat.h>

#define NATIVE_X86_STATE_VERSION 1

struct native_x86_cpu_state {
    struct pvkvm_cpuid_table cpuid;
    struct kvm_mp_state mp;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    struct kvm_xsave xsave;
    struct kvm_xcrs xcrs;
    struct kvm_debugregs debug;
    struct kvm_lapic_state lapic;
    struct kvm_vcpu_events events;
};

struct native_x86_state {
    unsigned char magic[8];
    uint32_t version;
    uint32_t cpu_count;
    uint32_t irqchip;
    uint32_t pit;
    struct pvkvm_cpuid_table host_cpuid;
    struct kvm_irqchip chips[KVM_NR_IRQCHIPS];
    struct kvm_pit_state2 timer;
    struct native_x86_cpu_state cpus[PVKVM_MAX_CPUS];
};

static const unsigned char native_x86_magic[8] = {'F', 'L', 'E', 'X', 'K', 'V', 'M', 'X'};

static int native_x86_io(int fd, void *state, size_t length, bool write_state)
{
    unsigned char *bytes = state;
    for (size_t offset = 0; offset < length;) {
        ssize_t done = write_state ? pwrite(fd, bytes + offset, length - offset, offset) :
                                     pread(fd, bytes + offset, length - offset, offset);
        if (done < 0 && errno == EINTR)
            continue;
        if (done <= 0)
            return done < 0 ? -errno : -EIO;
        offset += done;
    }
    return 0;
}

static int native_x86_save_cpu(int cpu, bool irqchip, struct native_x86_cpu_state *state)
{
    state->cpuid.count = PVKVM_CPUID_MAX;
    if (ioctl(cpu, KVM_GET_MP_STATE, &state->mp) < 0 ||
        ioctl(cpu, KVM_GET_REGS, &state->regs) < 0 ||
        ioctl(cpu, KVM_GET_SREGS, &state->sregs) < 0 ||
        ioctl(cpu, KVM_GET_XSAVE, &state->xsave) < 0 ||
        ioctl(cpu, KVM_GET_XCRS, &state->xcrs) < 0 ||
        ioctl(cpu, KVM_GET_DEBUGREGS, &state->debug) < 0 ||
        (irqchip && ioctl(cpu, KVM_GET_LAPIC, &state->lapic) < 0) ||
        ioctl(cpu, KVM_GET_CPUID2, &state->cpuid) < 0 ||
        ioctl(cpu, KVM_GET_VCPU_EVENTS, &state->events) < 0)
        return -errno;
    return 0;
}

static int native_x86_restore_cpu(int cpu, bool irqchip, struct native_x86_cpu_state *state)
{
    if (state->cpuid.count > PVKVM_CPUID_MAX)
        return -EINVAL;
    if (ioctl(cpu, KVM_SET_CPUID2, &state->cpuid) < 0 ||
        ioctl(cpu, KVM_SET_MP_STATE, &state->mp) < 0 ||
        ioctl(cpu, KVM_SET_REGS, &state->regs) < 0 ||
        ioctl(cpu, KVM_SET_SREGS, &state->sregs) < 0 ||
        ioctl(cpu, KVM_SET_XSAVE, &state->xsave) < 0 ||
        ioctl(cpu, KVM_SET_XCRS, &state->xcrs) < 0 ||
        ioctl(cpu, KVM_SET_DEBUGREGS, &state->debug) < 0 ||
        (irqchip && ioctl(cpu, KVM_SET_LAPIC, &state->lapic) < 0) ||
        ioctl(cpu, KVM_SET_VCPU_EVENTS, &state->events) < 0)
        return -errno;
    return 0;
}

static int native_x86_state_file(int fd, int kvm, int vm, const int *cpus, unsigned int cpu_count,
                                 bool irqchip, unsigned int pit, bool save)
{
    if (!cpu_count || cpu_count > PVKVM_MAX_CPUS)
        return -EINVAL;
    struct stat mode;
    if (fstat(fd, &mode) < 0)
        return -errno;
    if (!S_ISREG(mode.st_mode) || mode.st_size != (save ? 0 : (off_t)sizeof(struct native_x86_state)))
        return -EINVAL;
    int xsave_bytes = ioctl(vm, KVM_CHECK_EXTENSION, KVM_CAP_XSAVE2);
    if (xsave_bytes > PVKVM_XSAVE_BYTES)
        return -EOPNOTSUPP;
    if (xsave_bytes < 0)
        return -errno;

    struct native_x86_state *state = calloc(1, sizeof(*state));
    if (!state)
        return -ENOMEM;
    struct pvkvm_cpuid_table host;
    memset(&host, 0, sizeof(host));
    host.count = PVKVM_CPUID_MAX;
    int status = 0;
    if (ioctl(kvm, KVM_GET_SUPPORTED_CPUID, &host) < 0) {
        status = -errno;
        goto finished;
    }
    if (host.count > PVKVM_CPUID_MAX) {
        status = -E2BIG;
        goto finished;
    }
    // APIC IDs describe the physical CPU that answered the host probe.
    for (unsigned int index = 0; index < host.count; index++) {
        struct kvm_cpuid_entry2 *entry = &host.entries[index];
        if (entry->function == 1)
            entry->ebx &= 0x00ffffff;
        if (entry->function == 0xb || entry->function == 0x1f)
            entry->edx = 0;
    }
    if (save) {
        memcpy(state->magic, native_x86_magic, sizeof(state->magic));
        state->version = NATIVE_X86_STATE_VERSION;
        state->cpu_count = cpu_count;
        state->irqchip = irqchip;
        state->pit = pit;
        state->host_cpuid = host;
        for (unsigned int id = 0; id < cpu_count && !status; id++)
            status = native_x86_save_cpu(cpus[id], irqchip, &state->cpus[id]);
        for (unsigned int chip = 0; irqchip && chip < KVM_NR_IRQCHIPS && !status; chip++) {
            state->chips[chip].chip_id = chip;
            if (ioctl(vm, KVM_GET_IRQCHIP, &state->chips[chip]) < 0)
                status = -errno;
        }
        if (!status && pit && ioctl(vm, KVM_GET_PIT2, &state->timer) < 0)
            status = -errno;
        if (!status)
            status = native_x86_io(fd, state, sizeof(*state), true);
    } else {
        status = native_x86_io(fd, state, sizeof(*state), false);
        if (status)
            goto finished;
        if (memcmp(state->magic, native_x86_magic, sizeof(state->magic)) ||
            state->version != NATIVE_X86_STATE_VERSION || state->cpu_count != cpu_count ||
            state->irqchip != irqchip || state->pit != pit || state->host_cpuid.count != host.count ||
            memcmp(state->host_cpuid.entries, host.entries, host.count * sizeof(host.entries[0]))) {
            status = -EINVAL;
            goto finished;
        }
        for (unsigned int chip = 0; irqchip && chip < KVM_NR_IRQCHIPS && !status; chip++) {
            if (state->chips[chip].chip_id != chip)
                status = -EINVAL;
            else if (ioctl(vm, KVM_SET_IRQCHIP, &state->chips[chip]) < 0)
                status = -errno;
        }
        if (!status && pit && ioctl(vm, KVM_SET_PIT2, &state->timer) < 0)
            status = -errno;
        for (unsigned int id = 0; id < cpu_count && !status; id++)
            status = native_x86_restore_cpu(cpus[id], irqchip, &state->cpus[id]);
    }
finished:
    free(state);
    return status;
}

#endif
