/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLEXVM_ARM_NATIVE_WIRE_H
#define FLEXVM_ARM_NATIVE_WIRE_H

#include <linux/kvm.h>
#include <stdint.h>

/* Native ARM commands use one SOCK_SEQPACKET record per request and reply. */
enum flexvm_arm_command {
    FLEXVM_ARM_PREFERRED_TARGET = 1,
    FLEXVM_ARM_CREATE_VCPU,
    FLEXVM_ARM_INIT_VCPU,
    FLEXVM_ARM_GET_REG_LIST,
    FLEXVM_ARM_GET_ONE_REG,
    FLEXVM_ARM_SET_ONE_REG,
    FLEXVM_ARM_RUN,
    FLEXVM_ARM_REGISTER_RAM,
    FLEXVM_ARM_OPEN_LANE,
    FLEXVM_ARM_CANCEL_RUN,
    FLEXVM_ARM_COMPLETE_READ,
    FLEXVM_ARM_CLOSE_VCPU,
};

#define FLEXVM_ARM_MAX_REGS 4096
#define FLEXVM_ARM_MAX_CPUS 2
#define FLEXVM_ARM_MAX_SLOTS 8
#define FLEXVM_ARM_MAX_REG_BYTES 256
#define FLEXVM_ARM_RAM_BASE UINT64_C(0x40000000)
#define FLEXVM_ARM_RAM_LIMIT UINT64_C(0xc0000000)

struct flexvm_arm_request {
    uint32_t command;
    uint32_t cpu;
    uint32_t sequence;
    uint32_t reserved;
    union {
        struct kvm_vcpu_init init;
        struct {
            uint64_t id;
            uint8_t data[FLEXVM_ARM_MAX_REG_BYTES];
        } reg;
        struct {
            uint64_t address;
            uint32_t slot;
            uint32_t reserved;
        } ram;
        uint64_t count;
        uint8_t completion[8];
    };
};

struct flexvm_arm_reply {
    int32_t status;
    uint32_t exit_reason;
    union {
        struct kvm_vcpu_init init;
        uint8_t reg_data[FLEXVM_ARM_MAX_REG_BYTES];
        uint64_t count;
        struct {
            uint64_t address;
            uint32_t length;
            uint32_t is_write;
            uint8_t data[8];
        } mmio;
        struct {
            uint32_t type;
            uint32_t count;
            uint64_t data[16];
        } event;
    };
};

_Static_assert(sizeof(struct flexvm_arm_request) == 280, "ARM worker request layout");
_Static_assert(sizeof(struct flexvm_arm_reply) == 264, "ARM worker reply layout");

#endif
