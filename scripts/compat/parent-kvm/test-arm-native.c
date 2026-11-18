/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    ASSERT(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, link) == 0);
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
    ASSERT(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, link) == 0);
    pid_t worker = fork();
    ASSERT(worker >= 0);
    if (!worker) {
        close(link[0]);
        char peer_arg[24], ipa_arg[24];
        snprintf(peer_arg, sizeof(peer_arg), "%d", link[1]);
        snprintf(ipa_arg, sizeof(ipa_arg), "%d", ipa_bits > 48 ? 48 : ipa_bits);
        execl(argv[1], argv[1], peer_arg, ipa_arg, NULL);
        _exit(127);
    }
    close(link[1]);

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

    close(link[0]);
    int status;
    ASSERT(waitpid(worker, &status, 0) == worker && WIFEXITED(status) && !WEXITSTATUS(status));
    ASSERT(close(lane[0]) == 0 && close(lane[1]) == 0);
    puts("PASS native ARM concurrent runs and exact cancellation");
    puts("PASS native ARM worker VM, vCPU initialization, register state, MMIO, shared page, and PSCI");
    return 0;
}
