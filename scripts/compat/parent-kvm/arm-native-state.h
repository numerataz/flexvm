/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLEXVM_ARM_NATIVE_STATE_H
#define FLEXVM_ARM_NATIVE_STATE_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define FLEXVM_ARM_CORE_RECORDS 1024
#define FLEXVM_ARM_CORE_BYTES 16

struct arm_core_register {
    uint64_t id;
    unsigned char value[FLEXVM_ARM_CORE_BYTES];
};

struct arm_timer_state {
    uint64_t virtual_counter;
    uint64_t virtual_compare;
    uint64_t virtual_control;
    uint64_t physical_counter;
    uint64_t physical_compare;
    uint64_t physical_control;
    uint64_t physical_available;
};

struct arm_core_state {
    unsigned char magic[8];
    uint32_t version;
    uint32_t count;
    struct kvm_mp_state mp;
    uint32_t reserved;
    uint64_t frequency;
    struct arm_timer_state timers;
    struct kvm_vcpu_events events;
    struct arm_core_register registers[FLEXVM_ARM_CORE_RECORDS];
};

static const unsigned char arm_core_magic[8] = {'F', 'L', 'E', 'X', 'A', 'R', 'M', 'C'};

static int arm_state_io(int fd, void *state, size_t length, bool writing)
{
    unsigned char *bytes = state;
    for (size_t offset = 0; offset < length;) {
        ssize_t done = writing ? pwrite(fd, bytes + offset, length - offset, offset) :
                                 pread(fd, bytes + offset, length - offset, offset);
        if (done < 0 && errno == EINTR)
            continue;
        if (done <= 0)
            return done < 0 ? -errno : -EIO;
        offset += done;
    }
    return 0;
}

static bool arm_state_register(uint64_t id)
{
    uint64_t kind = id & (KVM_REG_ARCH_MASK | KVM_REG_ARM_COPROC_MASK);
    if (kind == (KVM_REG_ARM64 | KVM_REG_ARM_CORE) || kind == (KVM_REG_ARM64 | KVM_REG_ARM_DEMUX) ||
        kind == (KVM_REG_ARM64 | KVM_REG_ARM_FW))
        return true;
    if (kind != (KVM_REG_ARM64 | KVM_REG_ARM64_SYSREG))
        return false;
    switch (id) {
    case KVM_REG_ARM_TIMER_CNT:
    case KVM_REG_ARM_TIMER_CTL:
    case KVM_REG_ARM_TIMER_CVAL:
    case KVM_REG_ARM_PTIMER_CNT:
    case KVM_REG_ARM_PTIMER_CTL:
    case KVM_REG_ARM_PTIMER_CVAL:
        return false;
    default:
        return true;
    }
}

static int arm_timer_register(int cpu, uint64_t id, uint64_t *value, bool save)
{
    struct kvm_one_reg reg = {.id = id, .addr = (uintptr_t)value};
    return ioctl(cpu, save ? KVM_GET_ONE_REG : KVM_SET_ONE_REG, &reg);
}

static int arm_timers_state(int cpu, unsigned int id, struct arm_timer_state *state, bool save)
{
    uint64_t counter;
    bool physical = arm_timer_register(cpu, KVM_REG_ARM_PTIMER_CNT, &counter, true) == 0;
    if (!physical) {
        if (errno != ENOENT && errno != EINVAL)
            return -errno;
        if (save) {
            uint64_t control;
            if (arm_timer_register(cpu, KVM_REG_ARM_PTIMER_CTL, &control, true) == 0 && (control & 1))
                return -EOPNOTSUPP;
        }
    }
    if (save) {
        state->physical_available = physical;
        if (physical)
            state->physical_counter = counter;
        if (!id && arm_timer_register(cpu, KVM_REG_ARM_TIMER_CNT, &state->virtual_counter, true) < 0)
            return -errno;
    } else {
        if (state->physical_available != physical)
            return -EINVAL;
        // Some KVM kernels keep the guest physical counter at host time.
        // Preserve the remaining time on its compare register instead.
        if (physical)
            state->physical_compare += counter - state->physical_counter;
        // CNTVCT sets a VM-wide offset. Only the first vCPU carries it.
        if (!id && arm_timer_register(cpu, KVM_REG_ARM_TIMER_CNT, &state->virtual_counter, false) < 0)
            return -errno;
    }
    if (arm_timer_register(cpu, KVM_REG_ARM_TIMER_CVAL, &state->virtual_compare, save) < 0 ||
        (physical && arm_timer_register(cpu, KVM_REG_ARM_PTIMER_CVAL, &state->physical_compare, save) < 0) ||
        arm_timer_register(cpu, KVM_REG_ARM_TIMER_CTL, &state->virtual_control, save) < 0 ||
        (physical && arm_timer_register(cpu, KVM_REG_ARM_PTIMER_CTL, &state->physical_control, save) < 0))
        return -errno;
    return 0;
}

static int arm_core_state_file(int cpu, unsigned int vcpu_id, int fd, struct kvm_reg_list *list, bool save)
{
    struct stat mode;
    if (fstat(fd, &mode) < 0)
        return -errno;
    if (!S_ISREG(mode.st_mode) || mode.st_size != (save ? 0 : (off_t)sizeof(struct arm_core_state)))
        return -EINVAL;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -errno;
    if ((save && ((flags & O_ACCMODE) == O_RDONLY || flags & O_APPEND)) ||
        (!save && (flags & O_ACCMODE) == O_WRONLY))
        return -EBADF;

    uint64_t ids[FLEXVM_ARM_CORE_RECORDS];
    size_t count = 0;
    list->n = FLEXVM_ARM_MAX_REGS;
    if (ioctl(cpu, KVM_GET_REG_LIST, list) < 0)
        return -errno;
    if (list->n > FLEXVM_ARM_MAX_REGS)
        return -EOVERFLOW;
    for (size_t index = 0; index < list->n; index++) {
        uint64_t id = list->reg[index];
        if ((id & (KVM_REG_ARCH_MASK | KVM_REG_ARM_COPROC_MASK)) == (KVM_REG_ARM64 | KVM_REG_ARM64_SVE))
            return -EOPNOTSUPP;
        if (!arm_state_register(id))
            continue;
        size_t bytes = KVM_REG_SIZE(id);
        if (count == FLEXVM_ARM_CORE_RECORDS || (bytes != 4 && bytes != 8 && bytes != FLEXVM_ARM_CORE_BYTES))
            return -EOVERFLOW;
        ids[count++] = id;
    }
    if (!count)
        return -ENXIO;

    uint64_t frequency;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    struct arm_core_state state = {0};
    if (save) {
        memcpy(state.magic, arm_core_magic, sizeof(state.magic));
        state.version = 2;
        state.count = count;
        state.frequency = frequency;
        int status = arm_timers_state(cpu, vcpu_id, &state.timers, true);
        if (status)
            return status;
        if (ioctl(cpu, KVM_GET_MP_STATE, &state.mp) < 0 ||
            ioctl(cpu, KVM_GET_VCPU_EVENTS, &state.events) < 0)
            return -errno;
        for (size_t index = 0; index < count; index++)
            state.registers[index].id = ids[index];
    } else {
        int status = arm_state_io(fd, &state, sizeof(state), false);
        if (status)
            return status;
        if (memcmp(state.magic, arm_core_magic, sizeof(state.magic)) ||
            state.version != 2 || state.count != count || state.reserved || state.frequency != frequency)
            return -EINVAL;
        for (size_t index = 0; index < count; index++) {
            if (state.registers[index].id != ids[index])
                return -EINVAL;
        }
    }

    for (size_t index = 0; index < count; index++) {
        struct kvm_one_reg reg = {
            .id = ids[index], .addr = (uintptr_t)state.registers[index].value,
        };
        if (ioctl(cpu, save ? KVM_GET_ONE_REG : KVM_SET_ONE_REG, &reg) >= 0)
            continue;
        int error = errno;
        if (!save && (error == EINVAL || error == ENOENT || error == EPERM)) {
            unsigned char current[FLEXVM_ARM_CORE_BYTES] = {0};
            reg.addr = (uintptr_t)current;
            if (ioctl(cpu, KVM_GET_ONE_REG, &reg) == 0 && !memcmp(current, state.registers[index].value, KVM_REG_SIZE(ids[index])))
                continue;
        }
        fprintf(stderr, "native ARM worker: %s register %#llx failed: %s\n",
                save ? "saving" : "restoring", (unsigned long long)ids[index], strerror(error));
        return -error;
    }
    if (save)
        return arm_state_io(fd, &state, sizeof(state), true);
    int status = arm_timers_state(cpu, vcpu_id, &state.timers, false);
    if (status)
        return status;
    return ioctl(cpu, KVM_SET_VCPU_EVENTS, &state.events) < 0 ||
           ioctl(cpu, KVM_SET_MP_STATE, &state.mp) < 0 ? -errno : 0;
}

#endif
