/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "arm-native-wire.h"
#include "arm-native-state.h"
#include "arm-vgic.h"
#include "slot-map.h"

#if !defined(__aarch64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error The native ARM worker requires little-endian AArch64.
#endif

struct arm_cpu {
    int fd;
    struct kvm_run *run;
    uint32_t pending_read;
    int initialized;
    uint32_t id;
    int lane;
    pthread_t thread;
    pthread_mutex_t execution;
    atomic_uint admitted;
    atomic_uint completed;
};

struct arm_vm {
    int fd;
    size_t run_bytes;
    struct arm_cpu cpus[FLEXVM_ARM_MAX_CPUS];
    int vgic[2];
    bool wired_irqs[FLEXVM_ARM_GSI_COUNT];
    struct {
        uint64_t address;
        size_t bytes;
    } slots[FLEXVM_ARM_MAX_SLOTS];
    size_t ram_bytes;
    int lanes_opened;
};

static _Thread_local struct kvm_run *active_run_page;
static _Thread_local volatile sig_atomic_t active_sequence;
static _Thread_local volatile sig_atomic_t cancelled_sequence;
static _Thread_local volatile sig_atomic_t stop_requested;

static void interrupt_run(int number, siginfo_t *info, void *context)
{
    (void)number;
    (void)context;
    if (info->si_code != SI_QUEUE || info->si_value.sival_int <= 0)
        return;
    sig_atomic_t sequence = info->si_value.sival_int;
    if (sequence > cancelled_sequence)
        cancelled_sequence = sequence;
    if (active_sequence == sequence)
        __atomic_store_n(&active_run_page->immediate_exit, 1, __ATOMIC_RELAXED);
}

static void terminate_lane(int signal)
{
    (void)signal;
    stop_requested = 1;
    if (active_sequence)
        __atomic_store_n(&active_run_page->immediate_exit, 1, __ATOMIC_RELAXED);
}

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
    __atomic_store_n(&run->immediate_exit, 0, __ATOMIC_RELAXED);
    atomic_signal_fence(memory_order_seq_cst);
    active_sequence = request->sequence;
    if (active_sequence && (stop_requested || active_sequence == cancelled_sequence))
        __atomic_store_n(&run->immediate_exit, 1, __ATOMIC_RELAXED);
    int status = ioctl_result(ioctl(cpu->fd, KVM_RUN, 0));
    active_sequence = 0;
    /* KVM completes the previous userspace read before an interrupted run. */
    if (!status || status == -EINTR || status == -EAGAIN)
        cpu->pending_read = 0;
    if (status)
        return status;
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

static int complete_read(struct arm_cpu *cpu, const struct flexvm_arm_request *request)
{
    if (!cpu->pending_read)
        return -EINVAL;
    struct kvm_run *run = cpu->run;
    memcpy(run->mmio.data, request->completion, cpu->pending_read);
    __atomic_store_n(&run->immediate_exit, 1, __ATOMIC_RELAXED);
    int status = ioctl_result(ioctl(cpu->fd, KVM_RUN, 0));
    __atomic_store_n(&run->immediate_exit, 0, __ATOMIC_RELAXED);
    if (status != -EINTR)
        return status ? status : -EIO;
    cpu->pending_read = 0;
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
    case FLEXVM_ARM_GET_MP_STATE:
    case FLEXVM_ARM_SET_MP_STATE: {
        struct kvm_mp_state state = {.mp_state = request->mp_state};
        int set = request->command == FLEXVM_ARM_SET_MP_STATE;
        int status = ioctl_result(ioctl(cpu->fd, set ? KVM_SET_MP_STATE : KVM_GET_MP_STATE, &state));
        if (!status && !set)
            reply->mp_state = state.mp_state;
        return status;
    }
    default:
        return -ENOTTY;
    }
}

static int device_ioctl(struct arm_vm *vm, const struct flexvm_arm_request *request, struct flexvm_arm_reply *reply)
{
    int id = arm_vgic_index(request->device.type);
    if (id < 0 || request->device.reserved)
        return -ENODEV;
    if (request->command == FLEXVM_ARM_CREATE_DEVICE) {
        struct kvm_create_device create = {.type = request->device.type, .flags = request->device.flags};
        if (create.flags & ~KVM_CREATE_DEVICE_TEST)
            return -EINVAL;
        if (!create.flags && vm->vgic[id] >= 0)
            return -EEXIST;
        int status = ioctl_result(ioctl(vm->fd, KVM_CREATE_DEVICE, &create));
        if (!status && !create.flags)
            vm->vgic[id] = create.fd;
        return status;
    }
    int fd = vm->vgic[id];
    if (fd < 0)
        return -EBADF;
    if (request->command == FLEXVM_ARM_CLOSE_DEVICE) {
        vm->vgic[id] = -1;
        return ioctl_result(close(fd));
    }
    int bytes = arm_vgic_attribute_size(request->device.type, request->device.group, request->device.attribute);
    if (bytes < 0 || request->device.flags)
        return -ENXIO;
    uint64_t value = request->device.value;
    struct kvm_device_attr attribute = {
        .group = request->device.group, .attr = request->device.attribute, .addr = bytes ? (uintptr_t)&value : 0,
    };
    if (request->command == FLEXVM_ARM_HAS_DEVICE_ATTR)
        return ioctl_result(ioctl(fd, KVM_HAS_DEVICE_ATTR, &attribute));
    if (request->command == FLEXVM_ARM_SET_DEVICE_ATTR)
        return ioctl_result(ioctl(fd, KVM_SET_DEVICE_ATTR, &attribute));
    if (!bytes)
        return -ENXIO;
    value = 0;
    int status = ioctl_result(ioctl(fd, KVM_GET_DEVICE_ATTR, &attribute));
    if (!status)
        reply->device_value = value;
    return status;
}

static int bind_irqfd(struct arm_vm *vm, uint32_t gsi, int fd)
{
    if (gsi >= FLEXVM_ARM_GSI_COUNT)
        return -EINVAL;
    if (vm->wired_irqs[gsi])
        return 0;
    struct kvm_irqfd irq = {.fd = fd, .gsi = gsi};
    int status = ioctl_result(ioctl(vm->fd, KVM_IRQFD, &irq));
    if (!status)
        vm->wired_irqs[gsi] = true;
    return status;
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

static void discard_descriptors(struct worker_packet *packet)
{
    for (unsigned int index = 0; index < packet->count; index++)
        if (packet->descriptors[index] >= 0)
            close(packet->descriptors[index]);
}

static void *serve_lane(void *opaque)
{
    struct arm_cpu *cpu = opaque;
    uint32_t previous = 0;
    active_run_page = cpu->run;
    while (!stop_requested) {
        struct worker_packet packet = {0};
        ssize_t received = receive_packet(cpu->lane, &packet);
        if (received < 0 && errno == EINTR)
            continue;
        if (received <= 0)
            break;
        const struct flexvm_arm_request *request = &packet.request;
        struct flexvm_arm_reply reply = {0};
        if (!packet.well_formed || packet.count || request->reserved ||
            (request->command != FLEXVM_ARM_RUN && request->command != FLEXVM_ARM_COMPLETE_READ) ||
            request->cpu != cpu->id ||
            request->sequence != previous + 1 || request->sequence > INT_MAX) {
            reply.status = -EPROTO;
        } else {
            previous = request->sequence;
            atomic_store(&cpu->admitted, previous);
            int lock = pthread_mutex_lock(&cpu->execution);
            if (lock) {
                reply.status = -lock;
            } else {
                reply.status = request->command == FLEXVM_ARM_RUN ?
                               run_cpu(cpu, request, &reply) : complete_read(cpu, request);
                pthread_mutex_unlock(&cpu->execution);
            }
            atomic_store(&cpu->completed, previous);
        }
        discard_descriptors(&packet);
        if (send(cpu->lane, &reply, sizeof(reply), MSG_NOSIGNAL) != sizeof(reply))
            break;
    }
    return NULL;
}

static int open_lane(struct arm_vm *vm, struct arm_cpu *cpu, struct worker_packet *packet)
{
    if (!cpu->initialized || !vm->ram_bytes)
        return -ENOEXEC;
    if (cpu->lane >= 0)
        return -EEXIST;
    int descriptor = packet->descriptors[0];
    int type;
    socklen_t size = sizeof(type);
    if (getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &size) < 0 || type != SOCK_SEQPACKET)
        return -EINVAL;
    cpu->lane = descriptor;
    int result = pthread_create(&cpu->thread, NULL, serve_lane, cpu);
    if (result) {
        cpu->lane = -1;
        return -result;
    }
    packet->descriptors[0] = -1;
    vm->lanes_opened = 1;
    return 0;
}

static void stop_lane(struct arm_cpu *cpu)
{
    if (cpu->lane < 0)
        return;
    pthread_kill(cpu->thread, SIGUSR1);
    shutdown(cpu->lane, SHUT_RDWR);
    pthread_join(cpu->thread, NULL);
    close(cpu->lane);
    cpu->lane = -1;
}

static int close_cpu(struct arm_vm *vm, struct arm_cpu *cpu)
{
    if (cpu->fd < 0)
        return -EBADF;
    stop_lane(cpu);
    int status = ioctl_result(munmap(cpu->run, vm->run_bytes));
    close(cpu->fd);
    cpu->fd = -1;
    cpu->run = NULL;
    cpu->initialized = 0;
    return status;
}

static int control_cpu(struct arm_cpu *cpu, const struct flexvm_arm_request *request,
                       struct flexvm_arm_reply *reply, struct kvm_reg_list *list)
{
    if (request->command == FLEXVM_ARM_CANCEL_RUN) {
        if (cpu->lane < 0 || !request->sequence || request->sequence > INT_MAX)
            return -EINVAL;
        unsigned int admitted = atomic_load(&cpu->admitted);
        unsigned int completed = atomic_load(&cpu->completed);
        if (request->sequence <= completed)
            return 0;
        // The next run can be cancelled before its packet arrives on the lane.
        // An unfinished current run owns the only pending cancellation.
        if (request->sequence != admitted &&
            (request->sequence != admitted + 1 || completed < admitted))
            return -EINVAL;
        return -pthread_sigqueue(cpu->thread, SIGRTMIN, (union sigval){.sival_int = request->sequence});
    }
    int lock = pthread_mutex_trylock(&cpu->execution);
    if (lock)
        return -lock;
    int result = request_cpu(cpu, request, reply, list);
    pthread_mutex_unlock(&cpu->execution);
    return result;
}

static int checkpoint_core(struct arm_vm *vm, const struct flexvm_arm_request *request, int fd, struct kvm_reg_list *list)
{
    unsigned int locked = 0;
    int status = 0;
    for (; locked < FLEXVM_ARM_MAX_CPUS; locked++) {
        int lock = pthread_mutex_trylock(&vm->cpus[locked].execution);
        if (lock) {
            status = -lock;
            break;
        }
    }
    if (!status) {
        struct arm_cpu *cpu = &vm->cpus[request->cpu];
        if (!cpu->initialized)
            status = -ENOEXEC;
        for (unsigned int id = 0; !status && id < FLEXVM_ARM_MAX_CPUS; id++) {
            const struct arm_cpu *peer = &vm->cpus[id];
            if (peer->pending_read || atomic_load(&peer->admitted) != atomic_load(&peer->completed))
                status = -EBUSY;
        }
        if (!status)
            status = arm_core_state_file(cpu->fd, request->cpu, fd, list, request->command == FLEXVM_ARM_SAVE_CORE);
    }
    while (locked > 0)
        pthread_mutex_unlock(&vm->cpus[--locked].execution);
    return status;
}

static void stop_lanes(struct arm_vm *vm)
{
    for (uint32_t id = 0; id < FLEXVM_ARM_MAX_CPUS; id++) {
        struct arm_cpu *cpu = &vm->cpus[id];
        if (cpu->lane < 0)
            continue;
        pthread_kill(cpu->thread, SIGUSR1);
        shutdown(cpu->lane, SHUT_RDWR);
    }
    for (uint32_t id = 0; id < FLEXVM_ARM_MAX_CPUS; id++) {
        struct arm_cpu *cpu = &vm->cpus[id];
        if (cpu->lane >= 0) {
            pthread_join(cpu->thread, NULL);
            close(cpu->lane);
        }
    }
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
        unsigned int descriptors_needed = 0;
        if (request->command == FLEXVM_ARM_REGISTER_RAM)
            descriptors_needed = 2;
        else if (request->command == FLEXVM_ARM_OPEN_LANE || request->command == FLEXVM_ARM_BIND_IRQFD ||
                 request->command == FLEXVM_ARM_SAVE_CORE || request->command == FLEXVM_ARM_RESTORE_CORE)
            descriptors_needed = 1;
        if (!packet.well_formed || packet.count != descriptors_needed || request->reserved ||
            (request->sequence && request->command != FLEXVM_ARM_CANCEL_RUN)) {
            reply.status = -EPROTO;
        } else if (request->command == FLEXVM_ARM_REGISTER_RAM) {
            reply.status = vm->lanes_opened ? -EBUSY : register_ram(vm, request, packet.descriptors[0], packet.descriptors[1]);
        } else if (request->command == FLEXVM_ARM_BIND_IRQFD) {
            reply.status = bind_irqfd(vm, request->gsi, packet.descriptors[0]);
        } else if (request->command >= FLEXVM_ARM_CREATE_DEVICE && request->command <= FLEXVM_ARM_HAS_DEVICE_ATTR) {
            reply.status = device_ioctl(vm, request, &reply);
        } else if (request->command == FLEXVM_ARM_PREFERRED_TARGET) {
            reply.status = ioctl_result(ioctl(vm->fd, KVM_ARM_PREFERRED_TARGET, &reply.init));
        } else if (request->cpu >= FLEXVM_ARM_MAX_CPUS) {
            reply.status = -EINVAL;
        } else if (request->command == FLEXVM_ARM_SAVE_CORE || request->command == FLEXVM_ARM_RESTORE_CORE) {
            reply.status = checkpoint_core(vm, request, packet.descriptors[0], list);
        } else if (request->command == FLEXVM_ARM_CREATE_VCPU) {
            reply.status = create_cpu(vm, request->cpu);
        } else if (request->command == FLEXVM_ARM_CLOSE_VCPU) {
            reply.status = close_cpu(vm, &vm->cpus[request->cpu]);
        } else if (request->command == FLEXVM_ARM_OPEN_LANE) {
            reply.status = open_lane(vm, &vm->cpus[request->cpu], &packet);
        } else if (request->command == FLEXVM_ARM_RUN || request->command == FLEXVM_ARM_COMPLETE_READ) {
            reply.status = -EOPNOTSUPP;
        } else {
            reply.status = control_cpu(&vm->cpus[request->cpu], request, &reply, list);
        }
        discard_descriptors(&packet);

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
    stop_lanes(vm);
}

static int open_kvm(void)
{
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "open ARM KVM");
    return kvm;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--ipa-bits")) {
        int kvm = open_kvm();
        check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_IMMEDIATE_EXIT) == 1, "query ARM run cancellation");
        int bits = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
        check(bits >= 32 && bits <= 52, "query ARM IPA size");
        printf("%d\n", bits);
        close(kvm);
        return 0;
    }
    check(argc == 3, "expected ARM worker control FD and VM type");
    int control = number(argv[1], INT_MAX);
    int socket_type;
    socklen_t socket_type_size = sizeof(socket_type);
    check(getsockopt(control, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_size) == 0 &&
          socket_type == SOCK_SEQPACKET, "expected ARM worker packet socket");
    unsigned long type = number(argv[2], KVM_VM_TYPE_ARM_IPA_SIZE_MASK);
    struct sigaction action = {.sa_sigaction = interrupt_run, .sa_flags = SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    check(sigaction(SIGRTMIN, &action, NULL) == 0, "install ARM run cancellation signal");
    struct sigaction stop = {.sa_handler = terminate_lane};
    sigemptyset(&stop.sa_mask);
    check(sigaction(SIGUSR1, &stop, NULL) == 0, "install ARM lane termination signal");
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGRTMIN);
    sigaddset(&signals, SIGUSR1);
    check(pthread_sigmask(SIG_UNBLOCK, &signals, NULL) == 0, "enable ARM worker signals");
    int kvm = open_kvm();
    check(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_IMMEDIATE_EXIT) == 1, "enable ARM KVM run cancellation");
    int run_bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    check(run_bytes >= (int)sizeof(struct kvm_run), "get the ARM KVM run mapping size");
    struct arm_vm vm = {.fd = ioctl(kvm, KVM_CREATE_VM, type), .run_bytes = run_bytes, .vgic = {-1, -1}};
    struct flexvm_arm_reply startup = {.status = vm.fd < 0 ? -errno : 0};
    if (startup.status) {
        check(send(control, &startup, sizeof(startup), MSG_NOSIGNAL) == sizeof(startup), "send ARM VM creation error");
        return 1;
    }
    for (uint32_t id = 0; id < FLEXVM_ARM_MAX_CPUS; id++) {
        struct arm_cpu *cpu = &vm.cpus[id];
        cpu->id = id;
        cpu->fd = cpu->lane = -1;
        atomic_init(&cpu->admitted, 0);
        atomic_init(&cpu->completed, 0);
        check(pthread_mutex_init(&cpu->execution, NULL) == 0, "initialize ARM vCPU lock");
    }
    check(send(control, &startup, sizeof(startup), MSG_NOSIGNAL) == sizeof(startup), "announce the ARM VM");
    serve(&vm, control);
    return 0;
}
