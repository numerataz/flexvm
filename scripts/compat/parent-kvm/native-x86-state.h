/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLEXVM_NATIVE_X86_STATE_H
#define FLEXVM_NATIVE_X86_STATE_H

#include <asm/kvm_para.h>
#include <sys/stat.h>

#define NATIVE_X86_STATE_VERSION 2

/* Guest-writable registers outside the core and LAPIC state. Keep TSC
 * before the deadline and paravirtual time registers on restore. */
static const uint32_t native_x86_msrs[] = {
    0x3b,                   /* IA32_TSC_ADJUST */
    0x10,                   /* IA32_TSC */
    0x48,                   /* IA32_SPEC_CTRL */
    0x174, 0x175, 0x176,    /* IA32_SYSENTER_{CS,ESP,EIP} */
    0x1a0,                  /* IA32_MISC_ENABLE */
    0x1d9,                  /* IA32_DEBUGCTL */
    0x277, 0x2ff,           /* IA32_PAT and MTRR default type */
    0x6e0,                  /* IA32_TSC_DEADLINE */
    0xc0000081, 0xc0000082, 0xc0000083, 0xc0000084, /* STAR, LSTAR, CSTAR, SFMASK */
    0xc0000102, 0xc0000103, /* KERNEL_GS_BASE and TSC_AUX */
    MSR_KVM_WALL_CLOCK, MSR_KVM_SYSTEM_TIME,
    MSR_KVM_WALL_CLOCK_NEW, MSR_KVM_SYSTEM_TIME_NEW,
    MSR_KVM_ASYNC_PF_INT, MSR_KVM_ASYNC_PF_EN, MSR_KVM_STEAL_TIME,
    MSR_KVM_PV_EOI_EN, MSR_KVM_POLL_CONTROL,
};
#define NATIVE_X86_MSR_COUNT (sizeof(native_x86_msrs) / sizeof(native_x86_msrs[0]))

struct native_x86_msrs {
    uint32_t count;
    uint32_t reserved;
    struct kvm_msr_entry entries[NATIVE_X86_MSR_COUNT];
};


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
    uint32_t tsc_khz;
    struct native_x86_msrs msrs;
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
    struct kvm_clock_data clock;
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

static uint32_t native_x86_pv_features(const struct pvkvm_cpuid_table *cpuid)
{
    for (unsigned int index = 0; index < cpuid->count; index++) {
        const struct kvm_cpuid_entry2 *entry = &cpuid->entries[index];
        if (entry->function == KVM_CPUID_FEATURES)
            return entry->eax;
    }
    return 0;
}

static bool native_x86_msr_active(uint32_t msr, uint32_t pv_features)
{
    bool modern_clock = pv_features & (1u << KVM_FEATURE_CLOCKSOURCE2);
    switch (msr) {
    case MSR_KVM_WALL_CLOCK:
    case MSR_KVM_SYSTEM_TIME:
        return !modern_clock && (pv_features & (1u << KVM_FEATURE_CLOCKSOURCE));
    case MSR_KVM_WALL_CLOCK_NEW:
    case MSR_KVM_SYSTEM_TIME_NEW:
        return modern_clock;
    case MSR_KVM_ASYNC_PF_INT:
        return pv_features & (1u << KVM_FEATURE_ASYNC_PF_INT);
    case MSR_KVM_ASYNC_PF_EN:
        return pv_features & (1u << KVM_FEATURE_ASYNC_PF);
    case MSR_KVM_STEAL_TIME:
        return pv_features & (1u << KVM_FEATURE_STEAL_TIME);
    case MSR_KVM_PV_EOI_EN:
        return pv_features & (1u << KVM_FEATURE_PV_EOI);
    case MSR_KVM_POLL_CONTROL:
        return pv_features & (1u << KVM_FEATURE_POLL_CONTROL);
    default:
        return true;
    }
}

static int native_x86_save_msrs(int cpu, struct native_x86_msrs *saved, uint32_t pv_features)
{
    struct native_x86_msrs query = {.count = 1};
    for (size_t index = 0; index < NATIVE_X86_MSR_COUNT; index++) {
        uint32_t msr = native_x86_msrs[index];
        if (!native_x86_msr_active(msr, pv_features))
            continue;
        query.entries[0] = (struct kvm_msr_entry){.index = msr};
        int status = ioctl(cpu, KVM_GET_MSRS, &query);
        if (status < 0)
            return -errno;
        if (status == 1)
            saved->entries[saved->count++] = query.entries[0];
    }
    return 0;
}

static int native_x86_restore_msrs(int cpu, struct native_x86_msrs *saved, uint32_t pv_features)
{
    if (saved->count > NATIVE_X86_MSR_COUNT || saved->reserved)
        return -EINVAL;
    size_t found = 0;
    for (size_t index = 0; index < NATIVE_X86_MSR_COUNT && found < saved->count; index++) {
        const struct kvm_msr_entry *entry = &saved->entries[found];
        if (entry->index == native_x86_msrs[index] && !entry->reserved && native_x86_msr_active(entry->index, pv_features))
            found++;
    }
    if (found != saved->count)
        return -EINVAL;
    int result = ioctl(cpu, KVM_SET_MSRS, saved);
    if (result < 0)
        return -errno;
    if ((unsigned int)result > saved->count)
        return -EIO;
    if ((unsigned int)result < saved->count) {
        fprintf(stderr, "native parent worker: cannot restore MSR %#x\n", saved->entries[result].index);
        return -EOPNOTSUPP;
    }
    return 0;
}

static int native_x86_save_cpu(int cpu, bool irqchip, struct native_x86_cpu_state *state)
{
    state->cpuid.count = PVKVM_CPUID_MAX;
    int khz = ioctl(cpu, KVM_GET_TSC_KHZ, 0);
    if (khz <= 0)
        return khz < 0 ? -errno : -EIO;
    state->tsc_khz = khz;
    if (ioctl(cpu, KVM_GET_MP_STATE, &state->mp) < 0 ||
        ioctl(cpu, KVM_GET_REGS, &state->regs) < 0 ||
        ioctl(cpu, KVM_GET_SREGS, &state->sregs) < 0 ||
        ioctl(cpu, KVM_GET_XSAVE, &state->xsave) < 0 ||
        ioctl(cpu, KVM_GET_XCRS, &state->xcrs) < 0 ||
        ioctl(cpu, KVM_GET_DEBUGREGS, &state->debug) < 0 ||
        (irqchip && ioctl(cpu, KVM_GET_LAPIC, &state->lapic) < 0) ||
        ioctl(cpu, KVM_GET_CPUID2, &state->cpuid) < 0)
        return -errno;
    if (state->cpuid.count > PVKVM_CPUID_MAX)
        return -E2BIG;
    int status = native_x86_save_msrs(cpu, &state->msrs, native_x86_pv_features(&state->cpuid));
    if (!status && ioctl(cpu, KVM_GET_VCPU_EVENTS, &state->events) < 0)
        status = -errno;
    return status;
}

static int native_x86_restore_cpu(int cpu, bool irqchip, struct native_x86_cpu_state *state)
{
    if (state->cpuid.count > PVKVM_CPUID_MAX || !state->tsc_khz)
        return -EINVAL;
    int khz = ioctl(cpu, KVM_GET_TSC_KHZ, 0);
    if (khz <= 0)
        return khz < 0 ? -errno : -EIO;
    int64_t difference = (int64_t)state->tsc_khz - khz;
    if (difference < 0)
        difference = -difference;
    if (difference * 1000000 > (int64_t)state->tsc_khz * 250 &&
        ioctl(cpu, KVM_SET_TSC_KHZ, (unsigned long)state->tsc_khz) < 0)
        return -errno;
    if (ioctl(cpu, KVM_SET_CPUID2, &state->cpuid) < 0 ||
        ioctl(cpu, KVM_SET_MP_STATE, &state->mp) < 0 ||
        ioctl(cpu, KVM_SET_REGS, &state->regs) < 0 ||
        ioctl(cpu, KVM_SET_SREGS, &state->sregs) < 0 ||
        ioctl(cpu, KVM_SET_XSAVE, &state->xsave) < 0 ||
        ioctl(cpu, KVM_SET_XCRS, &state->xcrs) < 0 ||
        ioctl(cpu, KVM_SET_DEBUGREGS, &state->debug) < 0 ||
        (irqchip && ioctl(cpu, KVM_SET_LAPIC, &state->lapic) < 0))
        return -errno;
    int status = native_x86_restore_msrs(cpu, &state->msrs, native_x86_pv_features(&state->cpuid));
    if (!status && ioctl(cpu, KVM_SET_VCPU_EVENTS, &state->events) < 0)
        status = -errno;
    return status;
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
        struct kvm_clock_data clock = {0};
        if (ioctl(vm, KVM_GET_CLOCK, &clock) < 0)
            status = -errno;
        state->clock.clock = clock.clock;
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
        struct kvm_clock_data clock = {.clock = state->clock.clock};
        if (ioctl(vm, KVM_SET_CLOCK, &clock) < 0)
            status = -errno;
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
