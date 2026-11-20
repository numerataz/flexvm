/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLEXVM_ARM_NATIVE_GIC_STATE_H
#define FLEXVM_ARM_NATIVE_GIC_STATE_H

#define FLEXVM_ARM_GIC_MAX_REGS 4096

struct arm_gic_register {
    uint64_t attribute;
    uint64_t value;
    uint32_t group;
    uint32_t reserved;
};

struct arm_gic_state {
    unsigned char magic[8];
    uint32_t version;
    uint32_t irqs;
    uint32_t count;
    uint32_t reserved;
    struct arm_gic_register registers[FLEXVM_ARM_GIC_MAX_REGS];
};

static const unsigned char arm_gic_magic[8] = {'F', 'L', 'E', 'X', 'G', 'I', 'C', '3'};

static int arm_gic_layout_add(struct arm_gic_state *state, uint32_t group, uint64_t first, unsigned int words)
{
    if (words > FLEXVM_ARM_GIC_MAX_REGS - state->count)
        return -EOVERFLOW;
    for (unsigned int word = 0; word < words; word++) {
        struct arm_gic_register *entry = &state->registers[state->count++];
        entry->group = group;
        entry->attribute = first + 4 * word;
    }
    return 0;
}

static int arm_gic_layout(int gic, const int *cpus, struct arm_gic_state *state)
{
    const uint32_t dist = KVM_DEV_ARM_VGIC_GRP_DIST_REGS;
    const uint32_t redist = KVM_DEV_ARM_VGIC_GRP_REDIST_REGS;
    const uint32_t system = KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS;
    const uint32_t level = KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO;
    struct kvm_device_attr irqs = {
        .group = KVM_DEV_ARM_VGIC_GRP_NR_IRQS, .addr = (uintptr_t)&state->irqs,
    };
    if (ioctl(gic, KVM_GET_DEVICE_ATTR, &irqs) < 0)
        return -errno;
    if (state->irqs < 64 || state->irqs > 1024 || state->irqs % 32)
        return -EINVAL;

    // Distributor registers for SPIs. SGIs and PPIs belong to GICR below.
    const struct {
        uint32_t offset;
        unsigned int irqs_per_word;
    } ranges[] = {
        {0x0080, 32}, // IGROUPR
        {0x0180, 32}, {0x0100, 32}, // ICENABLER, ISENABLER
        {0x0c00, 16}, // ICFGR
        {0x0280, 32}, {0x0200, 32}, // ICPENDR, ISPENDR
        {0x0380, 32}, {0x0300, 32}, // ICACTIVER, ISACTIVER
        {0x0400, 4},  // IPRIORITYR
    };
    int status = arm_gic_layout_add(state, dist, 0x0010, 1); // STATUSR
    for (size_t index = 0; index < sizeof(ranges) / sizeof(ranges[0]) && !status; index++) {
        unsigned int lanes = ranges[index].irqs_per_word;
        status = arm_gic_layout_add(state, dist, ranges[index].offset + 4 * (32 / lanes), (state->irqs - 32) / lanes);
    }
    if (!status)
        status = arm_gic_layout_add(state, dist, 0x6100, (state->irqs - 32) * 2); // IROUTER
    for (uint32_t irq = 32; irq < state->irqs && !status; irq += 32)
        status = arm_gic_layout_add(state, level, irq, 1);
    if (!status)
        status = arm_gic_layout_add(state, dist, 0x0000, 1); // CTLR

    const uint32_t redistributor[] = {
        0x0010, 0x0014,                   // STATUSR, WAKER
        0x0070, 0x0074, 0x0078, 0x007c,   // PROPBASER, PENDBASER
        0x0000,                           // CTLR
        0x10080, 0x10180, 0x10100,        // IGROUPR, ICENABLER, ISENABLER
        0x10c00, 0x10c04,                // ICFGR
        0x10280, 0x10200, 0x10380, 0x10300, // pending, active
    };
    const uint64_t interface[] = {
        ARM64_SYS_REG(3, 0, 12, 12, 5), // SRE
        ARM64_SYS_REG(3, 0, 12, 12, 4), // CTLR
        ARM64_SYS_REG(3, 0, 4, 6, 0),   // PMR
        ARM64_SYS_REG(3, 0, 12, 8, 3), ARM64_SYS_REG(3, 0, 12, 12, 3), // BPR
        ARM64_SYS_REG(3, 0, 12, 12, 6), ARM64_SYS_REG(3, 0, 12, 12, 7), // IGRPEN
    };
    for (size_t cpu = 0; cpu < FLEXVM_ARM_MAX_CPUS && !status; cpu++) {
        if (cpus[cpu] < 0)
            continue;
        uint64_t mpidr;
        struct kvm_one_reg reg = {.id = ARM64_SYS_REG(3, 0, 0, 0, 5), .addr = (uintptr_t)&mpidr};
        if (ioctl(cpus[cpu], KVM_GET_ONE_REG, &reg) < 0)
            return -errno;
        uint64_t selector = ((mpidr & 0xffffff) | ((mpidr >> 8) & 0xff000000)) << KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT;
        for (size_t n = 0; n < sizeof(redistributor) / sizeof(redistributor[0]) && !status; n++)
            status = arm_gic_layout_add(state, redist, selector | redistributor[n], 1);
        if (!status)
            status = arm_gic_layout_add(state, redist, selector | 0x10400, 8);
        if (!status)
            status = arm_gic_layout_add(state, level, selector, 1);
        for (size_t n = 0; n < sizeof(interface) / sizeof(interface[0]) && !status; n++)
            status = arm_gic_layout_add(state, system, selector | (interface[n] & 0xffff), 1);
        uint64_t control = 0;
        struct kvm_device_attr ctl = {.group = system, .attr = selector | (interface[1] & 0xffff), .addr = (uintptr_t)&control};
        if (!status && ioctl(gic, KVM_GET_DEVICE_ATTR, &ctl) < 0)
            return -errno;
        unsigned int priority_bits = 1 + ((control >> 8) & 7);
        if (priority_bits < 5 || priority_bits > 7)
            return -EINVAL;
        unsigned int active_registers = 1u << (priority_bits - 5);
        uint64_t group0 = ARM64_SYS_REG(3, 0, 12, 8, 4) & 0xffff;
        uint64_t group1 = ARM64_SYS_REG(3, 0, 12, 9, 0) & 0xffff;
        for (unsigned int n = 0; n < active_registers && !status; n++) {
            status = arm_gic_layout_add(state, system, selector | (group0 + n), 1);
            if (!status)
                status = arm_gic_layout_add(state, system, selector | (group1 + n), 1);
        }

    }
    return status;
}

static int arm_gic_state_file(int gic, const int *cpus, int fd, bool save)
{
    if (gic < 0)
        return -ENODEV;
    struct stat mode;
    if (fstat(fd, &mode) < 0)
        return -errno;
    if (!S_ISREG(mode.st_mode) || mode.st_size != (save ? 0 : (off_t)sizeof(struct arm_gic_state)))
        return -EINVAL;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -errno;
    if ((save && ((flags & O_ACCMODE) == O_RDONLY || flags & O_APPEND)) ||
        (!save && (flags & O_ACCMODE) == O_WRONLY))
        return -EBADF;

    struct arm_gic_state *layout = calloc(1, sizeof(*layout));
    struct arm_gic_state *record = save ? layout : calloc(1, sizeof(*record));
    int status = -ENOMEM;
    if (!layout || !record)
        goto cleanup;

    memcpy(layout->magic, arm_gic_magic, sizeof(layout->magic));
    layout->version = 1;
    status = arm_gic_layout(gic, cpus, layout);
    if (status)
        goto cleanup;
    if (!save) {
        status = arm_state_io(fd, record, sizeof(*record), false);
        if (status)
            goto cleanup;
        if (memcmp(record->magic, layout->magic, sizeof(record->magic)) || record->version != layout->version ||
            record->irqs != layout->irqs || record->count != layout->count || record->reserved) {
            status = -EINVAL;
            goto cleanup;
        }
        for (size_t n = 0; n < record->count; n++) {
            if (record->registers[n].group != layout->registers[n].group ||
                record->registers[n].attribute != layout->registers[n].attribute || record->registers[n].reserved) {
                status = -EINVAL;
                goto cleanup;
            }
        }
    }
    for (size_t n = 0; n < record->count && !status; n++) {
        struct arm_gic_register *reg = &record->registers[n];
        struct kvm_device_attr attr = {.group = reg->group, .attr = reg->attribute, .addr = (uintptr_t)&reg->value};
        if (ioctl(gic, save ? KVM_GET_DEVICE_ATTR : KVM_SET_DEVICE_ATTR, &attr) < 0) {
            status = -errno;
            fprintf(stderr, "native ARM worker: VGIC group %u attribute %#llx: %s\n",
                    reg->group, (unsigned long long)reg->attribute, strerror(-status));
        }
    }
    if (!status && save)
        status = arm_state_io(fd, record, sizeof(*record), true);
cleanup:
    if (!save)
        free(record);
    free(layout);
    return status;
}

#endif
