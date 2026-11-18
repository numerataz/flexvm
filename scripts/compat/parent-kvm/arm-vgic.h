/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLEXVM_ARM_VGIC_H
#define FLEXVM_ARM_VGIC_H

/* These attributes configure the live interrupt controllers before boot. */
static inline int arm_vgic_index(__u32 type)
{
    switch (type) {
    case KVM_DEV_TYPE_ARM_VGIC_V3:
        return 0;
    case KVM_DEV_TYPE_ARM_VGIC_ITS:
        return 1;
    default:
        return -1;
    }
}

static inline int arm_vgic_attribute_size(__u32 type, __u32 group, __u64 attr)
{
    if (arm_vgic_index(type) < 0)
        return -1;
    if (group == KVM_DEV_ARM_VGIC_GRP_CTRL && attr == KVM_DEV_ARM_VGIC_CTRL_INIT)
        return 0;
    if (type == KVM_DEV_TYPE_ARM_VGIC_ITS)
        return group == KVM_DEV_ARM_VGIC_GRP_ADDR && attr == KVM_VGIC_ITS_ADDR_TYPE ? 8 : -1;
    if (group == KVM_DEV_ARM_VGIC_GRP_NR_IRQS && !attr)
        return 4;
    if (group == KVM_DEV_ARM_VGIC_GRP_ADDR &&
        (attr == KVM_VGIC_V3_ADDR_TYPE_DIST || attr == KVM_VGIC_V3_ADDR_TYPE_REDIST ||
         attr == KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION))
        return 8;
    return -1;
}

#define FLEXVM_ARM_GSI_COUNT 128

#endif
