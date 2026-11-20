/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "arm-native-wire.h"
enum { PAGE = 4096 };

#define ASSERT(test) do { if (!(test)) { \
    fprintf(stderr, "ARM worker check failed at line %d: %s (errno %d)\n", __LINE__, #test, errno); \
    exit(1); \
} } while (0)

struct result {
    struct flexvm_arm_reply reply;
    uint64_t regs[FLEXVM_ARM_MAX_REGS];
};

static struct flexvm_arm_reply exchange(int control, struct flexvm_arm_request request, struct result *result)
{
    ASSERT(send(control, &request, sizeof(request), MSG_NOSIGNAL) == sizeof(request));
    ssize_t bytes = recv(control, result, sizeof(*result), MSG_TRUNC);
    ASSERT(bytes >= (ssize_t)sizeof(result->reply));
    size_t count = request.command == FLEXVM_ARM_GET_REG_LIST && !result->reply.status ? result->reply.count : 0;
    ASSERT(count <= FLEXVM_ARM_MAX_REGS && (size_t)bytes == sizeof(result->reply) + count * sizeof(result->regs[0]));
    return result->reply;
}

static int pass_descriptors(int control, struct flexvm_arm_request request, const int *fds, size_t count)
{
    ASSERT(count == 1 || count == 2);
    struct iovec payload = {.iov_base = &request, .iov_len = sizeof(request)};
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(2 * sizeof(int))];
    } ancillary = {0};
    struct msghdr message = {
        .msg_iov = &payload, .msg_iovlen = 1, .msg_control = ancillary.bytes,
        .msg_controllen = CMSG_SPACE(count * sizeof(int)),
    };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(header), fds, count * sizeof(int));
    ASSERT(sendmsg(control, &message, MSG_NOSIGNAL) == sizeof(request));
    struct flexvm_arm_reply reply;
    ASSERT(recv(control, &reply, sizeof(reply), MSG_TRUNC) == sizeof(reply));
    return reply.status;
}

static int register_slot(int control, unsigned int slot, uint64_t address, int ram, int layout)
{
    struct flexvm_arm_request request = {.command = FLEXVM_ARM_REGISTER_RAM, .ram = {.address = address, .slot = slot}};
    const int descriptors[] = {ram, layout};
    return pass_descriptors(control, request, descriptors, 2);
}

static int open_lane(int control, unsigned int cpu)
{
    int link[2];
    ASSERT(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, link) == 0);
    struct flexvm_arm_request request = {.command = FLEXVM_ARM_OPEN_LANE, .cpu = cpu};
    ASSERT(pass_descriptors(control, request, &link[1], 1) == 0);
    ASSERT(close(link[1]) == 0);
    return link[0];
}

static void send_run(int lane, struct flexvm_arm_request request)
{
    ASSERT(send(lane, &request, sizeof(request), MSG_NOSIGNAL) == sizeof(request));
}

static struct flexvm_arm_reply read_reply(int lane)
{
    struct flexvm_arm_reply reply;
    ASSERT(recv(lane, &reply, sizeof(reply), MSG_TRUNC) == sizeof(reply));
    return reply;
}

static void cancel_run(int control, struct result *result, unsigned int cpu, unsigned int sequence)
{
    struct flexvm_arm_request command = {.command = FLEXVM_ARM_CANCEL_RUN, .cpu = cpu, .sequence = sequence};
    ASSERT(!exchange(control, command, result).status);
}

static uint64_t core_id(size_t offset)
{
    return KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (offset / sizeof(uint32_t));
}

static void write_and_read_register(int control, struct result *result, unsigned int cpu, uint64_t id,
                                    const void *value, size_t size)
{
    struct flexvm_arm_request request = {.command = FLEXVM_ARM_SET_ONE_REG, .cpu = cpu, .reg = {.id = id}};
    memcpy(request.reg.data, value, size);
    ASSERT(exchange(control, request, result).status == 0);
    request.command = FLEXVM_ARM_GET_ONE_REG;
    memset(request.reg.data, 0, size);
    struct flexvm_arm_reply reply = exchange(control, request, result);
    ASSERT(!reply.status && !memcmp(reply.reg_data, value, size));
}

static void set_core(int control, struct result *result, unsigned int cpu, size_t offset, uint64_t value)
{
    write_and_read_register(control, result, cpu, core_id(offset), &value, sizeof(value));
}

static pid_t start_worker(const char *path, int ipa_bits, int link[2])
{
    ASSERT(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, link) == 0);
    pid_t worker = fork();
    ASSERT(worker >= 0);
    if (!worker) {
        close(link[0]);
        ASSERT(fcntl(link[1], F_SETFD, 0) == 0);
        char peer_arg[24], ipa_arg[24];
        snprintf(peer_arg, sizeof(peer_arg), "%d", link[1]);
        snprintf(ipa_arg, sizeof(ipa_arg), "%d", ipa_bits > 48 ? 48 : ipa_bits);
        execl(path, path, peer_arg, ipa_arg, NULL);
        _exit(127);
    }
    close(link[1]);
    ASSERT(!read_reply(link[0]).status);

    return worker;
}

static void configure_gic(int socket, struct result *result)
{
    struct flexvm_arm_request request = {.command = FLEXVM_ARM_CREATE_DEVICE, .device = {.type = KVM_DEV_TYPE_ARM_VGIC_V3}};
    ASSERT(!exchange(socket, request, result).status);
    request.command = FLEXVM_ARM_SET_DEVICE_ATTR;
    request.device.group = KVM_DEV_ARM_VGIC_GRP_ADDR;
    request.device.attribute = KVM_VGIC_V3_ADDR_TYPE_DIST;
    request.device.value = UINT64_C(0x3fff0000);
    ASSERT(!exchange(socket, request, result).status);
    request.device.attribute = KVM_VGIC_V3_ADDR_TYPE_REDIST;
    request.device.value = UINT64_C(0x3ffb0000);
    ASSERT(!exchange(socket, request, result).status);
    request.device.group = KVM_DEV_ARM_VGIC_GRP_NR_IRQS;
    request.device.attribute = 0;
    request.device.value = 128;
    ASSERT(!exchange(socket, request, result).status);
    request.device.group = KVM_DEV_ARM_VGIC_GRP_CTRL;
    request.device.attribute = KVM_DEV_ARM_VGIC_CTRL_INIT;
    ASSERT(!exchange(socket, request, result).status);

    request = (struct flexvm_arm_request){.command = FLEXVM_ARM_CREATE_DEVICE, .device = {.type = KVM_DEV_TYPE_ARM_VGIC_ITS}};
    ASSERT(!exchange(socket, request, result).status);
    request.command = FLEXVM_ARM_SET_DEVICE_ATTR;
    request.device.group = KVM_DEV_ARM_VGIC_GRP_ADDR;
    request.device.attribute = KVM_VGIC_ITS_ADDR_TYPE;
    request.device.value = UINT64_C(0x3ff90000);
    ASSERT(!exchange(socket, request, result).status);
    request.device.group = KVM_DEV_ARM_VGIC_GRP_CTRL;
    request.device.attribute = KVM_DEV_ARM_VGIC_CTRL_INIT;
    ASSERT(!exchange(socket, request, result).status);
}

static void check_gic_checkpoint(int source, int target, struct result *result)
{
    int event = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    struct flexvm_arm_request bind = {.command = FLEXVM_ARM_BIND_IRQFD, .gsi = 3};
    ASSERT(event >= 0 && pass_descriptors(source, bind, &event, 1) == 0 && eventfd_write(event, 1) == 0);

    // The kernel queues IRQFD injection. Wait while the source stays fenced.
    ASSERT(poll(NULL, 0, 50) == 0);
    int gic = memfd_create("arm-native-gic-checkpoint", MFD_CLOEXEC);
    ASSERT(gic >= 0);
    struct flexvm_arm_request save = {.command = FLEXVM_ARM_SAVE_GIC};
    ASSERT(pass_descriptors(source, save, &gic, 1) == 0 && close(event) == 0);
    // Read GICD_ISPENDR1 and GITS_CBASER through the target's actual MMIO mappings.
    const uint32_t probe[] = {
        0xd2a7ffe6, 0xb94204c1, 0xd2a20000, 0xb9000001,
        0xd2a7ff28, 0xf9404102, 0xf9000402, 0x14000000,
    };
    const unsigned int seals = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int ram = memfd_create("arm-native-gic-probe", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    ASSERT(ram >= 0 && ftruncate(ram, 2 * PAGE) == 0 &&
           pwrite(ram, probe, sizeof(probe), 0) == sizeof(probe) && fcntl(ram, F_ADD_SEALS, seals) == 0);
    const uint64_t addresses[] = {FLEXVM_ARM_RAM_BASE, FLEXVM_ARM_RAM_BASE + 0x10000};
    for (unsigned int slot = 0; slot < 2; slot++) {
        uint64_t offset = slot * PAGE;
        int layout = memfd_create("arm-native-gic-layout", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        ASSERT(layout >= 0 && write(layout, &offset, sizeof(offset)) == sizeof(offset) &&
               fcntl(layout, F_ADD_SEALS, seals | F_SEAL_WRITE) == 0);
        ASSERT(register_slot(target, slot, addresses[slot], ram, layout) == 0 && close(layout) == 0);
    }
    ASSERT(close(ram) == 0);
    struct flexvm_arm_request restore = {.command = FLEXVM_ARM_RESTORE_GIC};
    ASSERT(pass_descriptors(target, restore, &gic, 1) == 0 && close(gic) == 0);
    set_core(target, result, 0, offsetof(struct kvm_regs, regs.pc), FLEXVM_ARM_RAM_BASE);
    int lane = open_lane(target, 0);
    send_run(lane, (struct flexvm_arm_request){.command = FLEXVM_ARM_RUN, .sequence = 1});
    struct flexvm_arm_reply reply = read_reply(lane);
    uint32_t pending;
    memcpy(&pending, reply.mmio.data, sizeof(pending));
    ASSERT(!reply.status && reply.exit_reason == KVM_EXIT_MMIO && reply.mmio.is_write &&
           reply.mmio.address == 0x10000000 && reply.mmio.length == sizeof(pending) && (pending & (1u << 3)));
    send_run(lane, (struct flexvm_arm_request){.command = FLEXVM_ARM_RUN, .sequence = 2});
    reply = read_reply(lane);
    uint64_t cbaser;
    memcpy(&cbaser, reply.mmio.data, sizeof(cbaser));
    ASSERT(!reply.status && reply.exit_reason == KVM_EXIT_MMIO && reply.mmio.is_write &&
           reply.mmio.address == 0x10000008 && reply.mmio.length == sizeof(cbaser) &&
           (cbaser & UINT64_C(0x8000fffffffff000)) == UINT64_C(0x8000000040010000));
    ASSERT(close(lane) == 0);
    puts("PASS native ARM ITS restored the guest command queue base");
    puts("PASS native ARM GICv3 restored a pending IRQFD interrupt");
}

int main(int argc, char *argv[])
{
    ASSERT(argc == 2);
    alarm(20);
    const unsigned int seals = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int ram = memfd_create("arm-native-ram", MFD_ALLOW_SEALING | MFD_CLOEXEC);
    ASSERT(ram >= 0 && ftruncate(ram, 4 * PAGE) == 0 && fcntl(ram, F_ADD_SEALS, seals) == 0);
    const uint64_t offsets[] = {3 * PAGE, PAGE};
    int layouts[2];
    for (unsigned int index = 0; index < 2; index++) {
        layouts[index] = memfd_create("arm-native-layout", MFD_ALLOW_SEALING | MFD_CLOEXEC);
        ASSERT(layouts[index] >= 0 && write(layouts[index], &offsets[index], sizeof(offsets[index])) == sizeof(offsets[index]));
        ASSERT(fcntl(layouts[index], F_ADD_SEALS, seals | F_SEAL_WRITE) == 0);
    }
    const uint32_t code[] = {
        // Configure SPI 35 as edge-triggered in GICD_ICFGR2.
        0xd2a7ffe6, 0x52801007, 0xb90c08c7,
        // Configure GITS_CBASER with a separate, 64 KiB-aligned guest slot.
        0xd2a7ff28, 0xd2a80029, 0xf2f00009, 0xf9004109,
        // CPU 0 releases the first flag and waits for CPU 1's flag.
        0x91002043, 0x91003044, 0x52800025, 0x889ffc65, 0x88dffc85, 0x34ffffe5,
        0xb9400001, // ldr w1, [x0] from the VMM's MMIO address
        0xb9000401, // str w1, [x0, #4] back through MMIO
        0xb9000041, // str w1, [x2] to the second shared page
        0xd2800100, // Begin the PSCI SYSTEM_OFF function number.
        0xf2b08000,
        0xd4000002, // hvc #0
    };
    const uint32_t peer_code[] = {
        // CPU 1 observes CPU 0's flag, releases its own, and keeps running.
        0x91002043, 0x91003044, 0x88dffc65, 0x34ffffe5, 0x52800025, 0x889ffc85, 0x14000000,
    };
    const uint64_t peer_entry = 256;
    ASSERT(pwrite(ram, code, sizeof(code), offsets[0]) == sizeof(code));
    ASSERT(pwrite(ram, peer_code, sizeof(peer_code), offsets[0] + peer_entry) == sizeof(peer_code));
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    ASSERT(kvm >= 0);
    int ipa_bits = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
    ASSERT(ipa_bits >= 32);
    ASSERT(close(kvm) == 0);
    int link[2];
    pid_t worker = start_worker(argv[1], ipa_bits, link);

    struct result result;
    ASSERT(send(link[0], "?", 1, MSG_NOSIGNAL) == 1);
    ASSERT(recv(link[0], &result.reply, sizeof(result.reply), MSG_TRUNC) == sizeof(result.reply) &&
           result.reply.status == -EPROTO);
    struct flexvm_arm_reply reply = exchange(link[0], (struct flexvm_arm_request){.command = FLEXVM_ARM_PREFERRED_TARGET}, &result);
    ASSERT(!reply.status);
    struct kvm_vcpu_init init = reply.init;
    init.features[0] |= 1U << KVM_ARM_VCPU_PSCI_0_2;
    for (unsigned int cpu = 0; cpu < 2; cpu++) {
        ASSERT(!exchange(link[0], (struct flexvm_arm_request){.command = FLEXVM_ARM_CREATE_VCPU, .cpu = cpu}, &result).status);
        ASSERT(!exchange(link[0], (struct flexvm_arm_request){.command = FLEXVM_ARM_INIT_VCPU, .cpu = cpu, .init = init}, &result).status);
    }
    configure_gic(link[0], &result);
    reply = exchange(link[0], (struct flexvm_arm_request){.command = FLEXVM_ARM_GET_REG_LIST}, &result);
    ASSERT(reply.status == -E2BIG && reply.count >= 34 && reply.count <= FLEXVM_ARM_MAX_REGS);
    reply = exchange(link[0], (struct flexvm_arm_request){.command = FLEXVM_ARM_GET_REG_LIST, .count = reply.count}, &result);
    ASSERT(!reply.status);
    uint64_t pc = core_id(offsetof(struct kvm_regs, regs.pc));
    unsigned int pc_ids = 0;
    for (size_t i = 0; i < reply.count; i++)
        pc_ids += result.regs[i] == pc;
    ASSERT(pc_ids == 1);

    uint32_t fpsr = 1;
    uint64_t vector[] = {UINT64_C(0x0011223344556677), UINT64_C(0x8899aabbccddeeff)};
    uint64_t register_namespace = KVM_REG_ARM64 | KVM_REG_ARM_CORE;
    write_and_read_register(link[0], &result, 0,
                            register_namespace | KVM_REG_SIZE_U32 | offsetof(struct kvm_regs, fp_regs.fpsr) / sizeof(uint32_t),
                            &fpsr, sizeof(fpsr));
    write_and_read_register(link[0], &result, 0,
                            register_namespace | KVM_REG_SIZE_U128 | offsetof(struct kvm_regs, fp_regs.vregs[0]) / sizeof(uint32_t),
                            vector, sizeof(vector));

    struct flexvm_arm_request run = {.command = FLEXVM_ARM_RUN};
    ASSERT(exchange(link[0], run, &result).status == -EOPNOTSUPP);
    struct flexvm_arm_request missing_fds = {.command = FLEXVM_ARM_REGISTER_RAM};
    ASSERT(exchange(link[0], missing_fds, &result).status == -EPROTO);
    int unsealed = memfd_create("unsealed-arm-layout", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    ASSERT(unsealed >= 0 && write(unsealed, &offsets[0], sizeof(offsets[0])) == sizeof(offsets[0]));
    ASSERT(register_slot(link[0], 0, FLEXVM_ARM_RAM_BASE, ram, unsealed) == -EINVAL);
    ASSERT(close(unsealed) == 0);
    ASSERT(register_slot(link[0], 0, FLEXVM_ARM_RAM_BASE, ram, layouts[0]) == 0);
    ASSERT(register_slot(link[0], 0, FLEXVM_ARM_RAM_BASE + 3 * PAGE, ram, layouts[1]) == -EEXIST);
    ASSERT(register_slot(link[0], 1, FLEXVM_ARM_RAM_BASE, ram, layouts[1]) == -EINVAL);
    ASSERT(register_slot(link[0], 1, FLEXVM_ARM_RAM_BASE + 3 * PAGE, ram, layouts[1]) == 0);
    ASSERT(close(layouts[0]) == 0 && close(layouts[1]) == 0);
    uint64_t queue_offset = 2 * PAGE;
    int queue = memfd_create("arm-native-its-queue-layout", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    ASSERT(queue >= 0 && write(queue, &queue_offset, sizeof(queue_offset)) == sizeof(queue_offset) &&
           fcntl(queue, F_ADD_SEALS, seals | F_SEAL_WRITE) == 0);
    ASSERT(register_slot(link[0], 2, FLEXVM_ARM_RAM_BASE + 0x10000, ram, queue) == 0 && close(queue) == 0);

    set_core(link[0], &result, 0, offsetof(struct kvm_regs, regs.pc), FLEXVM_ARM_RAM_BASE);
    set_core(link[0], &result, 0, offsetof(struct kvm_regs, regs.pstate), 0x3c5);
    set_core(link[0], &result, 0, offsetof(struct kvm_regs, regs.regs[0]), 0x10000000);
    set_core(link[0], &result, 0, offsetof(struct kvm_regs, regs.regs[2]), FLEXVM_ARM_RAM_BASE + 3 * PAGE);
    set_core(link[0], &result, 1, offsetof(struct kvm_regs, regs.pc), FLEXVM_ARM_RAM_BASE + peer_entry);
    set_core(link[0], &result, 1, offsetof(struct kvm_regs, regs.pstate), 0x3c5);
    set_core(link[0], &result, 1, offsetof(struct kvm_regs, regs.regs[2]), FLEXVM_ARM_RAM_BASE + 3 * PAGE);
    int lane[2] = {open_lane(link[0], 0), open_lane(link[0], 1)};
    run.sequence = 1;
    struct flexvm_arm_request peer_run = {.command = FLEXVM_ARM_RUN, .cpu = 1, .sequence = 1};
    send_run(lane[0], run);
    send_run(lane[1], peer_run);
    reply = read_reply(lane[0]);
    ASSERT(!reply.status && reply.exit_reason == KVM_EXIT_MMIO && reply.mmio.address == 0x10000000 &&
           reply.mmio.length == 4 && !reply.mmio.is_write);
    int checkpoint = memfd_create("arm-native-core-checkpoint", MFD_ALLOW_SEALING | MFD_CLOEXEC);
    ASSERT(checkpoint >= 0);
    struct flexvm_arm_request save = {.command = FLEXVM_ARM_SAVE_CORE};
    ASSERT(pass_descriptors(link[0], save, &checkpoint, 1) == -EBUSY);
    uint32_t flags[2];
    ASSERT(pread(ram, flags, sizeof(flags), offsets[1] + 8) == sizeof(flags) && flags[0] == 1 && flags[1] == 1);
    struct flexvm_arm_request future = {.command = FLEXVM_ARM_CANCEL_RUN, .cpu = 1, .sequence = 2};
    ASSERT(exchange(link[0], future, &result).status == -EINVAL);
    cancel_run(link[0], &result, 1, 1);
    ASSERT(read_reply(lane[1]).status == -EINTR);

    // A late duplicate cancellation must leave the next sequence running.
    cancel_run(link[0], &result, 1, 1);
    peer_run.sequence++;
    send_run(lane[1], peer_run);
    struct pollfd readable = {.fd = lane[1], .events = POLLIN};
    ASSERT(poll(&readable, 1, 50) == 0);
    cancel_run(link[0], &result, 1, 2);
    ASSERT(read_reply(lane[1]).status == -EINTR);
    // Cancellation can also arrive before the run on the other socket.
    cancel_run(link[0], &result, 1, 3);
    peer_run.sequence++;
    send_run(lane[1], peer_run);
    ASSERT(read_reply(lane[1]).status == -EINTR);

    const uint32_t pattern = 0x12345678;
    struct flexvm_arm_request completion = {.command = FLEXVM_ARM_COMPLETE_READ, .sequence = ++run.sequence};
    memcpy(completion.completion, &pattern, sizeof(pattern));
    send_run(lane[0], completion);
    reply = read_reply(lane[0]);
    ASSERT(!reply.status && !reply.exit_reason);
    struct flexvm_arm_request read_x1 = {
        .command = FLEXVM_ARM_GET_ONE_REG, .reg = {.id = core_id(offsetof(struct kvm_regs, regs.regs[1]))},
    };
    reply = exchange(link[0], read_x1, &result);
    uint64_t x1;
    memcpy(&x1, reply.reg_data, sizeof(x1));
    ASSERT(!reply.status && x1 == pattern);

    const uint64_t thread_id = UINT64_C(0x123456789abc);
    const uint64_t deadline = UINT64_C(0x876543210);
    const uint64_t counter = UINT64_C(0x123456789);
    const uint64_t tpidr_el1 = ARM64_SYS_REG(3, 0, 13, 0, 4);
    write_and_read_register(link[0], &result, 0, tpidr_el1, &thread_id, sizeof(thread_id));
    write_and_read_register(link[0], &result, 0, KVM_REG_ARM_TIMER_CVAL, &deadline, sizeof(deadline));
    struct flexvm_arm_request clock = {.command = FLEXVM_ARM_SET_ONE_REG, .reg = {.id = KVM_REG_ARM_TIMER_CNT}};
    memcpy(clock.reg.data, &counter, sizeof(counter));
    ASSERT(!exchange(link[0], clock, &result).status);
    uint64_t frequency, physical;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    const struct flexvm_arm_request physical_count = {.command = FLEXVM_ARM_GET_ONE_REG, .reg = {.id = KVM_REG_ARM_PTIMER_CNT}};
    reply = exchange(link[0], physical_count, &result);
    bool has_physical_counter = !reply.status;
    if (has_physical_counter) {
        memcpy(&physical, reply.reg_data, sizeof(physical));
        physical += 30 * frequency;
        write_and_read_register(link[0], &result, 0, KVM_REG_ARM_PTIMER_CVAL, &physical, sizeof(physical));
    } else {
        ASSERT(reply.status == -ENOENT || reply.status == -EINVAL);
    }

    ASSERT(pass_descriptors(link[0], save, &checkpoint, 1) == 0);
    ASSERT(fcntl(checkpoint, F_ADD_SEALS, seals | F_SEAL_WRITE) == 0);
    int target[2];
    pid_t replacement = start_worker(argv[1], ipa_bits, target);
    for (unsigned int cpu = 0; cpu < 2; cpu++) {
        ASSERT(!exchange(target[0], (struct flexvm_arm_request){.command = FLEXVM_ARM_CREATE_VCPU, .cpu = cpu}, &result).status);
        ASSERT(!exchange(target[0], (struct flexvm_arm_request){.command = FLEXVM_ARM_INIT_VCPU, .cpu = cpu, .init = init}, &result).status);
    }
    configure_gic(target[0], &result);
    struct flexvm_arm_request restore = {.command = FLEXVM_ARM_RESTORE_CORE};
    int malformed = memfd_create("arm-native-malformed-core", MFD_CLOEXEC);
    off_t size = lseek(checkpoint, 0, SEEK_END);
    ASSERT(size > 0 && malformed >= 0 && ftruncate(malformed, size) == 0);
    ASSERT(pass_descriptors(target[0], restore, &malformed, 1) == -EINVAL && close(malformed) == 0);
    ASSERT(pass_descriptors(target[0], restore, &checkpoint, 1) == 0 && close(checkpoint) == 0);
    reply = exchange(target[0], read_x1, &result);
    memcpy(&x1, reply.reg_data, sizeof(x1));
    ASSERT(!reply.status && x1 == pattern);
    const struct flexvm_arm_request read_vector = {
        .command = FLEXVM_ARM_GET_ONE_REG,
        .reg = {.id = register_namespace | KVM_REG_SIZE_U128 | offsetof(struct kvm_regs, fp_regs.vregs[0]) / sizeof(uint32_t)},
    };
    reply = exchange(target[0], read_vector, &result);
    ASSERT(!reply.status && !memcmp(reply.reg_data, vector, sizeof(vector)));
    const struct flexvm_arm_request read_thread = {.command = FLEXVM_ARM_GET_ONE_REG, .reg = {.id = tpidr_el1}};
    reply = exchange(target[0], read_thread, &result);
    ASSERT(!reply.status && !memcmp(reply.reg_data, &thread_id, sizeof(thread_id)));
    const struct flexvm_arm_request read_deadline = {.command = FLEXVM_ARM_GET_ONE_REG, .reg = {.id = KVM_REG_ARM_TIMER_CVAL}};
    reply = exchange(target[0], read_deadline, &result);
    ASSERT(!reply.status && !memcmp(reply.reg_data, &deadline, sizeof(deadline)));
    clock.command = FLEXVM_ARM_GET_ONE_REG;
    reply = exchange(target[0], clock, &result);
    uint64_t after;
    memcpy(&after, reply.reg_data, sizeof(after));
    ASSERT(!reply.status && after >= counter && after - counter < 3 * frequency);
    if (has_physical_counter) {
        reply = exchange(target[0], physical_count, &result);
        memcpy(&after, reply.reg_data, sizeof(after));
        ASSERT(!reply.status);
        const struct flexvm_arm_request physical_compare = {.command = FLEXVM_ARM_GET_ONE_REG, .reg = {.id = KVM_REG_ARM_PTIMER_CVAL}};
        reply = exchange(target[0], physical_compare, &result);
        memcpy(&physical, reply.reg_data, sizeof(physical));
        ASSERT(!reply.status && physical > after && physical - after >= 27 * frequency && physical - after <= 30 * frequency);
    }
    check_gic_checkpoint(link[0], target[0], &result);
    close(target[0]);
    int replacement_status;
    ASSERT(waitpid(replacement, &replacement_status, 0) == replacement && WIFEXITED(replacement_status) && !WEXITSTATUS(replacement_status));
    puts("PASS native ARM checkpoint restored core, vector, system register and timer state in a fresh worker");
    run.sequence++;
    send_run(lane[0], run);
    reply = read_reply(lane[0]);
    ASSERT(!reply.status && reply.exit_reason == KVM_EXIT_MMIO && reply.mmio.address == 0x10000004 &&
           reply.mmio.length == 4 && reply.mmio.is_write && !memcmp(reply.mmio.data, &pattern, sizeof(pattern)));
    peer_run.sequence++;
    send_run(lane[1], peer_run);
    ASSERT(poll(&readable, 1, 50) == 0);
    run.sequence++;
    send_run(lane[0], run);
    reply = read_reply(lane[0]);
    ASSERT(!reply.status && reply.exit_reason == KVM_EXIT_SYSTEM_EVENT && reply.event.type == KVM_SYSTEM_EVENT_SHUTDOWN);
    uint32_t observed;
    ASSERT(pread(ram, &observed, sizeof(observed), offsets[1]) == sizeof(observed) && observed == pattern);
    ASSERT(pread(ram, &observed, sizeof(observed), 2 * PAGE) == sizeof(observed) && observed == 0);

    for (unsigned int cpu = 0; cpu < 2; cpu++) {
        struct flexvm_arm_request close_cpu = {.command = FLEXVM_ARM_CLOSE_VCPU, .cpu = cpu};
        ASSERT(!exchange(link[0], close_cpu, &result).status);
    }
    struct flexvm_arm_request preferred = {.command = FLEXVM_ARM_PREFERRED_TARGET};
    ASSERT(!exchange(link[0], preferred, &result).status);
    close(link[0]);
    int status;
    ASSERT(waitpid(worker, &status, 0) == worker && WIFEXITED(status) && !WEXITSTATUS(status));
    ASSERT(close(lane[0]) == 0 && close(lane[1]) == 0);
    puts("PASS native ARM concurrent runs and exact cancellation");
    puts("PASS native ARM worker VM, vCPU initialization, register state, MMIO, shared page, and PSCI");
    return 0;
}
