/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "arm-native-wire.h"
#include "slot-map.h"

#if !defined(__aarch64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error The native ARM worker requires little-endian AArch64.
#endif

struct arm_cpu {
    int fd;
    struct kvm_run *run;
    uint32_t pending_read;
    int initialized;
};

struct arm_vm {
    int fd;
    size_t run_bytes;
    struct arm_cpu cpus[FLEXVM_ARM_MAX_CPUS];
    struct {
        uint64_t address;
        size_t bytes;
    } slots[FLEXVM_ARM_MAX_SLOTS];
    size_t ram_bytes;
};

static void check(int condition, const char *message)
{
    if (condition)
        return;
    perror(message);
    exit(1);
}

static uint64_t number(const char *argument, uint64_t limit)
{
    char *end;
    errno = 0;
    unsigned long long value = strtoull(argument, &end, 10);
    check(argument[0] >= '0' && argument[0] <= '9' && !*end && !errno && value <= limit, "invalid ARM worker argument");
    return value;
}

static int ioctl_result(int result)
{
    return result < 0 ? -errno : 0;
}

static int create_cpu(struct arm_vm *vm, uint32_t id)
{
    struct arm_cpu *cpu = &vm->cpus[id];
    if (cpu->fd >= 0)
        return -EEXIST;
    int fd = ioctl(vm->fd, KVM_CREATE_VCPU, (unsigned long)id);
    if (fd < 0)
        return -errno;
    cpu->run = mmap(NULL, vm->run_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (cpu->run == MAP_FAILED) {
        int error = errno;
        close(fd);
        return -error;
    }
    cpu->fd = fd;
    return 0;
}

static int run_cpu(struct arm_cpu *cpu, const struct flexvm_arm_request *request, struct flexvm_arm_reply *reply)
{
    struct kvm_run *run = cpu->run;
    if (cpu->pending_read)
        memcpy(run->mmio.data, request->completion, cpu->pending_read);
    if (ioctl(cpu->fd, KVM_RUN, 0) < 0)
        return -errno;
    cpu->pending_read = 0;
    if (run->exit_reason == KVM_EXIT_MMIO) {
        if (!run->mmio.len || run->mmio.len > sizeof(run->mmio.data))
            return -EIO;
        reply->mmio.address = run->mmio.phys_addr;
        reply->mmio.length = run->mmio.len;
        reply->mmio.is_write = run->mmio.is_write;
        if (run->mmio.is_write)
            memcpy(reply->mmio.data, run->mmio.data, run->mmio.len);
        else
            cpu->pending_read = run->mmio.len;
    } else if (run->exit_reason == KVM_EXIT_SYSTEM_EVENT) {
        if (run->system_event.ndata > sizeof(reply->event.data) / sizeof(reply->event.data[0]))
            return -EIO;
        reply->event.type = run->system_event.type;
        reply->event.count = run->system_event.ndata;
        size_t bytes = (reply->event.count ? reply->event.count : 1) * sizeof(reply->event.data[0]);
        memcpy(reply->event.data, run->system_event.data, bytes);
    } else {
        return -EOPNOTSUPP;
    }
    reply->exit_reason = run->exit_reason;
    return 0;
}

static int request_cpu(struct arm_cpu *cpu, const struct flexvm_arm_request *request,
                       struct flexvm_arm_reply *reply, struct kvm_reg_list *list)
{
    if (cpu->fd < 0)
        return -EBADF;
    if (request->command == FLEXVM_ARM_INIT_VCPU) {
        int status = ioctl_result(ioctl(cpu->fd, KVM_ARM_VCPU_INIT, &request->init));
        if (!status) {
            cpu->initialized = 1;
            cpu->pending_read = 0;
        }
        return status;
    }
    if (!cpu->initialized)
        return -ENOEXEC;
    switch (request->command) {
    case FLEXVM_ARM_GET_REG_LIST: {
        list->n = request->count < FLEXVM_ARM_MAX_REGS ? request->count : FLEXVM_ARM_MAX_REGS;
        int status = ioctl_result(ioctl(cpu->fd, KVM_GET_REG_LIST, list));
        reply->count = list->n;
        return list->n > FLEXVM_ARM_MAX_REGS ? -EOVERFLOW : status;
    }
    case FLEXVM_ARM_GET_ONE_REG:
    case FLEXVM_ARM_SET_ONE_REG: {
        size_t bytes = KVM_REG_SIZE(request->reg.id);
        if (bytes > sizeof(reply->reg_data))
            return -EOPNOTSUPP;
        int set = request->command == FLEXVM_ARM_SET_ONE_REG;
        if (set)
            memcpy(reply->reg_data, request->reg.data, bytes);
        struct kvm_one_reg reg = {.id = request->reg.id, .addr = (uintptr_t)reply->reg_data};
        return ioctl_result(ioctl(cpu->fd, set ? KVM_SET_ONE_REG : KVM_GET_ONE_REG, &reg));
    }
    case FLEXVM_ARM_RUN:
        return run_cpu(cpu, request, reply);
    default:
        return -ENOTTY;
    }
}

static int register_ram(struct arm_vm *vm, const struct flexvm_arm_request *request, int ram, int layout)
{
    uint64_t address = request->ram.address;
    unsigned int slot = request->ram.slot;
    if (slot >= FLEXVM_ARM_MAX_SLOTS || request->ram.reserved || address < FLEXVM_ARM_RAM_BASE ||
        address >= FLEXVM_ARM_RAM_LIMIT || address % FLEXVM_SLOT_PAGE_SIZE)
        return -EINVAL;
    if (vm->slots[slot].bytes)
        return -EEXIST;
    size_t bytes;
    void *mapping = flexvm_map_slot(ram, layout, &bytes);
    if (mapping == MAP_FAILED)
        return -errno;
    int status = -EINVAL;
    if (bytes > FLEXVM_ARM_RAM_LIMIT - address)
        goto unmap;
    if (bytes > (size_t)FLEXVM_SLOT_MAX_PAGES * FLEXVM_SLOT_PAGE_SIZE - vm->ram_bytes) {
        status = -ENOSPC;
        goto unmap;
    }
    for (unsigned int existing = 0; existing < FLEXVM_ARM_MAX_SLOTS; existing++) {
        uint64_t other = vm->slots[existing].address;
        size_t length = vm->slots[existing].bytes;
        if (length && address < other + length && other < address + bytes)
            goto unmap;
    }
    struct kvm_userspace_memory_region region = {
        .slot = slot, .guest_phys_addr = address, .memory_size = bytes, .userspace_addr = (uintptr_t)mapping,
    };
    status = ioctl_result(ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &region));
    if (status)
        goto unmap;
    vm->slots[slot].address = address;
    vm->slots[slot].bytes = bytes;
    vm->ram_bytes += bytes;
    return 0;

unmap:
    munmap(mapping, bytes);
    return status;
}

struct worker_packet {
    struct flexvm_arm_request request;
    int descriptors[2];
    unsigned int count;
    int well_formed;
};

static ssize_t receive_packet(int control, struct worker_packet *packet)
{
    struct iovec payload = {.iov_base = &packet->request, .iov_len = sizeof(packet->request)};
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(packet->descriptors))];
    } ancillary;
    struct msghdr message = {
        .msg_iov = &payload, .msg_iovlen = 1, .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes),
    };
    ssize_t received = recvmsg(control, &message, MSG_TRUNC | MSG_CMSG_CLOEXEC);
    if (received <= 0)
        return received;
    packet->well_formed = received == sizeof(packet->request) && !(message.msg_flags & MSG_CTRUNC);
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS) {
            packet->well_formed = 0;
            continue;
        }
        size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t index = 0; index < count; index++) {
            int descriptor;
            memcpy(&descriptor, CMSG_DATA(header) + index * sizeof(int), sizeof(descriptor));
            if (packet->count < sizeof(packet->descriptors) / sizeof(packet->descriptors[0]))
                packet->descriptors[packet->count++] = descriptor;
            else {
                packet->well_formed = 0;
                close(descriptor);
            }
        }
    }
    return received;
}

static void serve(struct arm_vm *vm, int control)
{
    struct kvm_reg_list *list = calloc(1, sizeof(*list) + FLEXVM_ARM_MAX_REGS * sizeof(list->reg[0]));
    check(list != NULL, "allocate ARM KVM register list");
    for (;;) {
        struct worker_packet packet = {0};
        ssize_t got = receive_packet(control, &packet);
        if (!got)
            break;
        if (got < 0 && errno == EINTR)
            continue;
        check(got >= 0, "read ARM KVM worker request");

        const struct flexvm_arm_request *request = &packet.request;
        struct flexvm_arm_reply reply = {0};
        unsigned int descriptors_needed = request->command == FLEXVM_ARM_REGISTER_RAM ? 2 : 0;
        if (!packet.well_formed || packet.count != descriptors_needed) {
            reply.status = -EPROTO;
        } else if (request->command == FLEXVM_ARM_REGISTER_RAM) {
            reply.status = register_ram(vm, request, packet.descriptors[0], packet.descriptors[1]);
        } else if (request->command == FLEXVM_ARM_PREFERRED_TARGET) {
            reply.status = ioctl_result(ioctl(vm->fd, KVM_ARM_PREFERRED_TARGET, &reply.init));
        } else if (request->cpu >= FLEXVM_ARM_MAX_CPUS) {
            reply.status = -EINVAL;
        } else if (request->command == FLEXVM_ARM_CREATE_VCPU) {
            reply.status = create_cpu(vm, request->cpu);
        } else if (request->command == FLEXVM_ARM_RUN && !vm->ram_bytes) {
            reply.status = -ENOEXEC;
        } else {
            reply.status = request_cpu(&vm->cpus[request->cpu], request, &reply, list);
        }
        for (unsigned int index = 0; index < packet.count; index++)
            close(packet.descriptors[index]);

        size_t registers = 0;
        if (!reply.status && request->command == FLEXVM_ARM_GET_REG_LIST) {
            check(list->n <= request->count, "received an invalid KVM register list");
            registers = list->n * sizeof(list->reg[0]);
        }
        struct iovec iov[] = {{&reply, sizeof(reply)}, {list->reg, registers}};
        struct msghdr message = {.msg_iov = iov, .msg_iovlen = registers ? 2 : 1};
        check(sendmsg(control, &message, MSG_NOSIGNAL) == (ssize_t)(sizeof(reply) + registers), "send ARM KVM reply");
    }
    free(list);
}

int main(int argc, char **argv)
{
    check(argc == 3, "expected ARM worker control FD and VM type");
    int control = number(argv[1], INT_MAX);
    int socket_type;
    socklen_t socket_type_size = sizeof(socket_type);
    check(getsockopt(control, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_size) == 0 &&
          socket_type == SOCK_SEQPACKET, "expected ARM worker packet socket");
    unsigned long type = number(argv[2], KVM_VM_TYPE_ARM_IPA_SIZE_MASK);
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "open ARM KVM");
    int run_bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    check(run_bytes >= (int)sizeof(struct kvm_run), "get the ARM KVM run mapping size");
    struct arm_vm vm = {.fd = ioctl(kvm, KVM_CREATE_VM, type), .run_bytes = run_bytes,
                        .cpus = {{.fd = -1}, {.fd = -1}}};
    check(vm.fd >= 0, "create the ARM KVM VM");
    serve(&vm, control);
    return 0;
}
