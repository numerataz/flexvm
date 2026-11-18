/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLEXVM_ARM_NATIVE_STATE_H
#define FLEXVM_ARM_NATIVE_STATE_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define FLEXVM_ARM_CORE_RECORDS 128
#define FLEXVM_ARM_CORE_BYTES 16

struct arm_core_register {
    uint64_t id;
    unsigned char value[FLEXVM_ARM_CORE_BYTES];
};

struct arm_core_state {
    unsigned char magic[8];
    uint32_t version;
    uint32_t count;
    struct kvm_mp_state mp;
    uint32_t reserved;
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

static int arm_core_state_file(int cpu, int fd, struct kvm_reg_list *list, bool save)
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
        if ((id & (KVM_REG_ARCH_MASK | KVM_REG_ARM_COPROC_MASK)) != (KVM_REG_ARM64 | KVM_REG_ARM_CORE))
            continue;
        size_t bytes = KVM_REG_SIZE(id);
        if (count == FLEXVM_ARM_CORE_RECORDS || (bytes != 4 && bytes != 8 && bytes != FLEXVM_ARM_CORE_BYTES))
            return -EOVERFLOW;
        ids[count++] = id;
    }
    if (!count)
        return -ENXIO;

    struct arm_core_state state = {0};
    if (save) {
        memcpy(state.magic, arm_core_magic, sizeof(state.magic));
        state.version = 1;
        state.count = count;
        if (ioctl(cpu, KVM_GET_MP_STATE, &state.mp) < 0)
            return -errno;
        for (size_t index = 0; index < count; index++)
            state.registers[index].id = ids[index];
    } else {
        int status = arm_state_io(fd, &state, sizeof(state), false);
        if (status)
            return status;
        if (memcmp(state.magic, arm_core_magic, sizeof(state.magic)) ||
            state.version != 1 || state.count != count || state.reserved)
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
        if (ioctl(cpu, save ? KVM_GET_ONE_REG : KVM_SET_ONE_REG, &reg) < 0)
            return -errno;
    }
    if (save)
        return arm_state_io(fd, &state, sizeof(state), true);
    return ioctl(cpu, KVM_SET_MP_STATE, &state.mp) < 0 ? -errno : 0;
}

#endif
