#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include "mailbox.h"
#include "slot-map.h"
#include "native-x86-state.h"

static _Thread_local struct kvm_run *run_page;
static _Thread_local volatile sig_atomic_t active_run;
static _Thread_local volatile sig_atomic_t cancelled_run;
static _Thread_local volatile sig_atomic_t stop_requested;

static void interrupt_run(int signal, siginfo_t *info, void *context)
{
    (void)signal;
    (void)context;
    if (info->si_code != SI_QUEUE || info->si_value.sival_int < 0)
        return;
    int seq = info->si_value.sival_int;
    if (seq == 0)
        stop_requested = 1;
    else if (seq > cancelled_run)
        cancelled_run = seq;
    if (active_run && (stop_requested || cancelled_run == active_run))
        __atomic_store_n(&run_page->immediate_exit, 1, __ATOMIC_RELAXED);
}

static void check(bool condition, const char *why)
{
    if (condition) return;
    fprintf(stderr, "native parent worker: %s (%s)\n", why, strerror(errno));
    exit(1);
}

static unsigned long number(const char *text, unsigned long maximum)
{
    char *end;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    check(text[0] >= '0' && text[0] <= '9' && !errno && !*end && value <= maximum,
          "invalid worker argument");
    return value;
}

static int host_kvm(void)
{
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    check(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION,
          "open a compatible host KVM device");
    return kvm;
}

static void supported_cpuid(void)
{
    struct pvkvm_cpuid_table table = {.count = PVKVM_CPUID_MAX};
    int kvm = host_kvm();
    check(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, &table) == 0 && table.count <= PVKVM_CPUID_MAX,
          "read the host supported CPUID table");
    size_t bytes = offsetof(struct pvkvm_cpuid_table, entries) + table.count * sizeof(table.entries[0]);
    check(write(STDOUT_FILENO, &table, bytes) == (ssize_t)bytes, "write the supported CPUID table");
    close(kvm);
}

static void reset_state(unsigned int id, bool irqchip, unsigned long operation,
                        const unsigned int *mp_states, unsigned int count)
{
    union {
        struct kvm_lapic_state lapic;
        struct kvm_sregs sregs;
        struct kvm_debugregs debugregs;
        struct kvm_mp_state mp;
        struct kvm_xcrs xcrs;
        struct kvm_xsave xsave;
        struct kvm_vcpu_events events;
    } state;
    size_t length = sizeof(state.sregs);
    if (operation == KVM_GET_LAPIC)
        length = sizeof(state.lapic);
    if (operation == KVM_GET_DEBUGREGS)
        length = sizeof(state.debugregs);
    if (operation == KVM_GET_MP_STATE)
        length = sizeof(state.mp);
    if (operation == KVM_GET_XCRS)
        length = sizeof(state.xcrs);
    if (operation == KVM_GET_XSAVE)
        length = sizeof(state.xsave);
    if (operation == KVM_GET_VCPU_EVENTS)
        length = sizeof(state.events);
    int kvm = host_kvm();
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0, "create a host reset-state VM");
    if (irqchip)
        check(ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create a host IRQ controller");
    int cpu = ioctl(vm, KVM_CREATE_VCPU, id);
    check(cpu >= 0, "create the host reset vCPU");
    for (unsigned int i = 0; i < count; i++) {
        state.mp.mp_state = mp_states[i];
        check(ioctl(cpu, KVM_SET_MP_STATE, &state.mp) == 0, "install the staged host MP state");
    }
    check(ioctl(cpu, operation, &state) == 0, "read the host reset state");
    check(write(STDOUT_FILENO, &state, length) == (ssize_t)length, "write the host reset record");
    close(cpu);
    close(vm);
    close(kvm);
}

struct pending_read {
    unsigned char *data;
    size_t length;
};

static void reset_irqchips(void)
{
    int kvm = host_kvm();
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0 && ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create a host reset irqchip");
    for (unsigned int id = 0; id < KVM_NR_IRQCHIPS; id++) {
        struct kvm_irqchip chip = {.chip_id = id};
        check(ioctl(vm, KVM_GET_IRQCHIP, &chip) == 0, "read the host reset irqchip");
        check(write(STDOUT_FILENO, &chip, sizeof(chip)) == sizeof(chip), "write the reset irqchip image");
    }
    close(vm);
    close(kvm);
}

static void query_unstarted_pit(unsigned int flags, bool restore)
{
    int kvm = host_kvm();
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    struct kvm_pit_config config = {.flags = flags};
    struct kvm_pit_state2 pit;

    check(vm >= 0 && ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create a host reset irqchip");
    check(ioctl(vm, KVM_CREATE_PIT2, &config) == 0, "create a host reset PIT");
    if (restore) {
        check(read(STDIN_FILENO, &pit, sizeof(pit)) == sizeof(pit), "read the staged PIT image");
        check(ioctl(vm, KVM_SET_PIT2, &pit) == 0, "install the staged PIT image");
    }
    check(ioctl(vm, KVM_GET_PIT2, &pit) == 0, "read the host reset PIT");
    check(write(STDOUT_FILENO, &pit, sizeof(pit)) == sizeof(pit), "write the reset PIT image");
    close(vm);
    close(kvm);
}

static void reset_clock(void)
{
    int kvm = host_kvm();
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    struct kvm_clock_data clock = {0};

    check(vm >= 0, "create a host reset clock VM");
    check(ioctl(vm, KVM_GET_CLOCK, &clock) == 0, "read the host VM clock");
    check(write(STDOUT_FILENO, &clock, sizeof(clock)) == sizeof(clock), "write the clock record");
    close(vm);
    close(kvm);
}

static struct pending_read reply_run(int control, struct kvm_run *run, int mapping_bytes)
{
    if (run->exit_reason == KVM_EXIT_MMIO) {
        unsigned int width = run->mmio.len;
        check(width == 1 || width == 2 || width == 4 || width == 8,
              "unexpected host MMIO access");
        unsigned char output[18] = {run->mmio.is_write ? 'M' : 'Q', width};
        memcpy(output + 2, &run->mmio.phys_addr, sizeof(run->mmio.phys_addr));
        if (run->mmio.is_write)
            memcpy(output + 10, run->mmio.data, width);
        check(write(control, output, sizeof(output)) == sizeof(output), "return a host MMIO exit");
        return run->mmio.is_write ? (struct pending_read){0} : (struct pending_read){run->mmio.data, width};
    }
    check(run->exit_reason == KVM_EXIT_IO && run->io.direction <= KVM_EXIT_IO_OUT &&
          (run->io.size == 1 || run->io.size == 2 || run->io.size == 4) &&
          run->io.count > 0 && run->io.count <= PVKVM_PIO_BYTES / run->io.size &&
          run->io.data_offset < (unsigned long)mapping_bytes, "invalid host port I/O exit");
    size_t length = (size_t)run->io.count * run->io.size;
    check(length <= (unsigned long)mapping_bytes - run->io.data_offset, "host I/O data outside run mapping");
    unsigned char *data = (unsigned char *)run + run->io.data_offset;
    bool is_write = run->io.direction == KVM_EXIT_IO_OUT;
    unsigned char output[8 + PVKVM_PIO_BYTES] = {is_write ? 'U' : 'V', run->io.size};
    memcpy(output + 2, &run->io.port, sizeof(run->io.port));
    memcpy(output + 4, &run->io.count, sizeof(run->io.count));
    if (is_write)
        memcpy(output + 8, data, length);
    size_t bytes = 8 + (is_write ? length : 0);
    check(write(control, output, bytes) == (ssize_t)bytes, "return a host port I/O exit");
    return is_write ? (struct pending_read){0} : (struct pending_read){data, length};
}

struct native_lane {
    int control;
    int cpu;
    unsigned int id;
    int mapping_bytes;
    struct kvm_run *run;
    struct pending_read input;
    bool pending_write;
    bool deferred_exit;
};

static void send_exit(struct native_lane *lane, int control)
{
    lane->input = reply_run(control, lane->run, lane->mapping_bytes);
    lane->pending_write = !lane->input.length;
}

static int settle_pending_write(struct native_lane *lane)
{
    if (lane->input.length || lane->deferred_exit)
        return -EAGAIN;
    if (!lane->pending_write)
        return 0;
    lane->run->immediate_exit = 1;
    int result = ioctl(lane->cpu, KVM_RUN, 0);
    int error = errno;
    lane->run->immediate_exit = 0;
    if (!result) {
        // A continuation exit still belongs to the next guest KVM_RUN.
        lane->deferred_exit = true;
        lane->pending_write = false;
        return -EAGAIN;
    }
    if (error != EINTR)
        return -error;
    lane->pending_write = false;
    return 0;
}

static void serve_cpu_request(struct native_lane *lane, int control,
                              const unsigned char *request, ssize_t received)
{
    struct kvm_run *run = lane->run;
    struct pending_read *pending = &lane->input;
    uint32_t sequence;
    const size_t header = 2 + sizeof(sequence);

    if (received == 2 && lane->control >= 0 && request[0] == 'D') {
        int32_t status = settle_pending_write(lane);
        check(write(control, &status, sizeof(status)) == sizeof(status), "reply to native I/O fence");
        return;
    }

    if (request[0] == 'E') {
        check(pending->length && received == (ssize_t)(2 + pending->length),
              "invalid completion-only read");
        memcpy(pending->data, request + 2, pending->length);
        run->immediate_exit = 1;
        check(ioctl(lane->cpu, KVM_RUN, 0) == -1 && errno == EINTR,
              "complete host I/O and stop before entry");
        run->immediate_exit = 0;
        *pending = (struct pending_read){0};
        check(write(control, "E", 1) == 1, "acknowledge completed host I/O");
        return;
    }

    check(received == (ssize_t)(header + pending->length) && request[0] == 'R',
          "invalid run request");
    memcpy(&sequence, request + 2, sizeof(sequence));
    check(sequence > 0 && sequence <= INT_MAX, "invalid run sequence");
    if (lane->deferred_exit) {
        lane->deferred_exit = false;
        send_exit(lane, control);
        return;
    }
    if (pending->length) {
        memcpy(pending->data, request + header, pending->length);
        *pending = (struct pending_read){0};
    }

    run_page = run;
    __atomic_store_n(&run->immediate_exit, 0, __ATOMIC_RELAXED);
    /* A queued signal for this sequence can arrive before KVM_RUN begins. */
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
    active_run = (sig_atomic_t)sequence;
    if (stop_requested || cancelled_run == active_run)
        __atomic_store_n(&run->immediate_exit, 1, __ATOMIC_RELAXED);
    int result;
    do {
        result = ioctl(lane->cpu, KVM_RUN, 0);
    } while (result < 0 && errno == EINTR && !stop_requested &&
             cancelled_run != (sig_atomic_t)sequence);
    active_run = 0;
    lane->pending_write = false;
    if (stop_requested)
        return;
    if (result < 0 && errno == EINTR && cancelled_run == (sig_atomic_t)sequence) {
        static const unsigned char interrupted[] = {'I', 0};
        check(write(control, interrupted, sizeof(interrupted)) == sizeof(interrupted),
              "acknowledge the stopped host vCPU");
        return;
    }
    if (result < 0 && errno == EAGAIN && lane->control >= 0) {
        static const unsigned char retry[] = {'A', 0};
        check(write(control, retry, sizeof(retry)) == sizeof(retry), "report host vCPU retry");
        return;
    }

    check(result == 0, "run host vCPU");
    send_exit(lane, control);
}

static void *serve_cpu_lane(void *opaque)
{
    struct native_lane *lane = opaque;
    unsigned char request[6 + PVKVM_PIO_BYTES];

    check(write(lane->control, "R", 1) == 1, "announce native vCPU readiness");
    while (!stop_requested) {
        ssize_t received = recv(lane->control, request, sizeof(request), MSG_TRUNC);
        if (!received)
            return NULL;
        if (received < 0 && errno == EINTR)
            continue;
        check(received >= 2 && received <= (ssize_t)sizeof(request) && request[1] == lane->id,
              "invalid native vCPU lane request");
        serve_cpu_request(lane, lane->control, request, received);
    }
    return NULL;
}

static int set_irqfds(int vm, const int *descriptors, bool attach)
{
    for (unsigned int gsi = 0; gsi < PVKVM_GSI_COUNT; gsi++) {
        struct kvm_irqfd irq = {
            .fd = descriptors[gsi], .gsi = gsi,
            .flags = attach ? 0 : KVM_IRQFD_FLAG_DEASSIGN,
        };
        if (ioctl(vm, KVM_IRQFD, &irq) == 0)
            continue;
        int error = errno;
        // Restore the original ownership if the transition stops partway.
        irq.flags ^= KVM_IRQFD_FLAG_DEASSIGN;
        while (gsi > 0) {
            gsi--;
            irq.fd = descriptors[gsi];
            irq.gsi = gsi;
            check(ioctl(vm, KVM_IRQFD, &irq) == 0, "rollback incomplete native IRQFD transition");
        }
        return -error;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--checkpoint-state")) {
        puts("flexvm-native-x86-checkpoint-1");
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--supported-cpuid")) {
        supported_cpuid();
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--reset-lapic")) {
        reset_state(number(argv[2], PVKVM_MAX_CPUS - 1), true, KVM_GET_LAPIC, NULL, 0);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "--reset-sregs")) {
        reset_state(number(argv[2], PVKVM_MAX_CPUS - 1), number(argv[3], 1), KVM_GET_SREGS, NULL, 0);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--reset-debugregs")) {
        reset_state(number(argv[2], PVKVM_MAX_CPUS - 1), false, KVM_GET_DEBUGREGS, NULL, 0);
        return 0;
    }
    if (argc >= 4 && argc <= 6 && !strcmp(argv[1], "--reset-mp")) {
        unsigned int states[2];
        unsigned int count = argc - 4;

        for (unsigned int i = 0; i < count; i++)
            states[i] = number(argv[i + 4], KVM_MP_STATE_AP_RESET_HOLD);
        reset_state(number(argv[2], PVKVM_MAX_CPUS - 1), number(argv[3], 1), KVM_GET_MP_STATE, states, count);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--reset-xcrs")) {
        reset_state(number(argv[2], PVKVM_MAX_CPUS - 1), false, KVM_GET_XCRS, NULL, 0);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--reset-xsave")) {
        reset_state(number(argv[2], PVKVM_MAX_CPUS - 1), false, KVM_GET_XSAVE, NULL, 0);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--reset-clock")) {
        reset_clock();
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "--reset-events")) {
        reset_state(number(argv[2], PVKVM_MAX_CPUS - 1), number(argv[3], 1), KVM_GET_VCPU_EVENTS, NULL, 0);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--reset-irqchips")) {
        reset_irqchips();
        return 0;
    }
    if (argc == 3 && (!strcmp(argv[1], "--reset-pit") || !strcmp(argv[1], "--staged-pit"))) {
        query_unstarted_pit(number(argv[2], KVM_PIT_SPEAKER_DUMMY), !strcmp(argv[1], "--staged-pit"));
        return 0;
    }
    check(argc >= 10, "expected control, outer RAM, vCPU count, device configuration, and slots");
    int control = (int)number(argv[1], INT_MAX);
    int outer_ram = (int)number(argv[2], INT_MAX);
    unsigned int cpu_count = number(argv[3], PVKVM_MAX_CPUS);
    bool irqchip = number(argv[4], 1);
    unsigned int pit_request = number(argv[5], KVM_PIT_SPEAKER_DUMMY + 1);
    unsigned long tss = number(argv[6], UINT32_MAX);
    int first_slot = 7 + (irqchip ? PVKVM_GSI_COUNT : 0);
    int first_lane = -1;
    check(first_slot < argc && cpu_count > 0, "at least one native vCPU and RAM slot");
    if (!strcmp(argv[first_slot], "--run-sockets")) {
        first_lane = first_slot + 1;
        first_slot = first_lane + cpu_count;
    }
    bool parallel = first_lane >= 0;
    check(argc >= first_slot + 3 && (argc - first_slot) % 3 == 0 &&
          (argc - first_slot) / 3 <= PVKVM_MAX_SLOTS, "invalid worker RAM slots or interrupt descriptors");

    int kvm = host_kvm();
    int bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    check(bytes >= (int)sizeof(struct kvm_run), "KVM run mapping size");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    check(vm >= 0, "create host VM");
    if (tss != UINT32_MAX)
        check(ioctl(vm, KVM_SET_TSS_ADDR, tss) == 0, "reserve the host VM TSS address");
    int irq_fds[PVKVM_GSI_COUNT];
    bool irqfds_attached = irqchip;
    if (irqchip) {
        check(ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create the host irqchip");
        for (unsigned int gsi = 0; gsi < PVKVM_GSI_COUNT; gsi++)
            irq_fds[gsi] = number(argv[7 + gsi], INT_MAX);
        int status = set_irqfds(vm, irq_fds, true);
        errno = -status;
        check(!status, "connect host IRQFD doorbells");
    }
    if (pit_request) {
        struct kvm_pit_config pit = {.flags = pit_request - 1};
        check(ioctl(vm, KVM_CREATE_PIT2, &pit) == 0, "create the host PIT");
    }
    for (int arg = first_slot; arg < argc; arg += 3) {
        int layout = (int)number(argv[arg], INT_MAX);
        uint64_t gpa = number(argv[arg + 1], UINT32_MAX);
        uint32_t id = number(argv[arg + 2], PVKVM_MAX_SLOTS - 1);
        size_t slot_bytes;
        void *slot = flexvm_map_slot(outer_ram, layout, &slot_bytes);
        check(slot != MAP_FAILED, "map a parent RAM slot");
        close(layout);
        struct kvm_userspace_memory_region memory = {
            .slot = id, .guest_phys_addr = gpa, .memory_size = slot_bytes,
            .userspace_addr = (uintptr_t)slot,
        };
        check(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &memory) == 0, "register a shared RAM slot");
    }
    close(outer_ram);
    int cpus[PVKVM_MAX_CPUS];
    struct kvm_run *runs[PVKVM_MAX_CPUS];
    struct native_lane lanes[PVKVM_MAX_CPUS];
    pthread_t threads[PVKVM_MAX_CPUS];
    struct kvm_sregs segments;
    for (unsigned int id = 0; id < cpu_count; id++) {
        cpus[id] = ioctl(vm, KVM_CREATE_VCPU, id);
        check(cpus[id] >= 0, "create host vCPU");
        runs[id] = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, cpus[id], 0);
        check(runs[id] != MAP_FAILED, "map host kvm_run");
        check(ioctl(cpus[id], KVM_GET_SREGS, &segments) == 0, "read reset segments");
        segments.cs.base = 0;
        segments.cs.selector = 0;
        check(ioctl(cpus[id], KVM_SET_SREGS, &segments) == 0, "select real-mode code segment");
        lanes[id] = (struct native_lane){
            .control = parallel ? (int)number(argv[first_lane + id], INT_MAX) : -1,
            .cpu = cpus[id], .id = id, .mapping_bytes = bytes, .run = runs[id],
        };
    }
    struct sigaction action = {.sa_sigaction = interrupt_run, .sa_flags = SA_SIGINFO | SA_RESTART};
    check(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGRTMIN, &action, NULL) == 0,
          "install the native run interrupt handler");
    if (parallel) {
        for (unsigned int id = 0; id < cpu_count; id++) {
            errno = pthread_create(&threads[id], NULL, serve_cpu_lane, &lanes[id]);
            check(!errno, "start the native vCPU thread");
        }
    }
    struct kvm_regs registers;
    struct kvm_fpu fpu;
    struct kvm_lapic_state lapic;
    struct pvkvm_msr_batch msrs;
    struct pvkvm_cpuid_table cpuid;
    _Static_assert(sizeof(fpu) == PVKVM_FPU_BYTES && sizeof(cpuid) >= sizeof(fpu) &&
                   sizeof(struct kvm_pit_state2) == PVKVM_PIT_STATE_BYTES &&
                   sizeof(struct kvm_debugregs) == PVKVM_DEBUGREGS_BYTES &&
                   sizeof(struct kvm_xcrs) == PVKVM_XCRS_BYTES &&
                   sizeof(struct kvm_xsave) == PVKVM_XSAVE_BYTES && sizeof(cpuid) >= PVKVM_XSAVE_BYTES &&
                   sizeof(struct kvm_vcpu_events) == PVKVM_VCPU_EVENTS_BYTES &&
                   sizeof(struct kvm_clock_data) == PVKVM_CLOCK_BYTES &&
                   sizeof(lapic) == PVKVM_LAPIC_BYTES && sizeof(cpuid) >= sizeof(lapic) &&
                   sizeof(cpuid) >= PVKVM_PIO_BYTES + sizeof(uint32_t) &&
                   sizeof(cpuid) >= sizeof(segments) && sizeof(cpuid) >= sizeof(msrs),
                   "native worker control record size");

    check(write(control, "R", 1) == 1, "announce worker readiness");
    unsigned char request[2 + sizeof(cpuid)];
    for (;;) {
        union {
            struct cmsghdr header;
            unsigned char bytes[CMSG_SPACE(sizeof(int))];
        } ancillary;
        struct iovec data = {.iov_base = request, .iov_len = sizeof(request)};
        struct msghdr message = {
            .msg_iov = &data, .msg_iovlen = 1,
            .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes),
        };
        ssize_t received = recvmsg(control, &message, MSG_TRUNC | MSG_CMSG_CLOEXEC);
        if (received < 0 && errno == EINTR)
            continue;
        if (received == 0)
            break;
        check(received >= 2 && received <= (ssize_t)sizeof(request) && request[1] < cpu_count &&
              !(message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)), "invalid native worker request");
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        if (received == 2 && (request[0] == 'a' || request[0] == 'b')) {
            int fd;
            check(parallel && request[1] == 0 && header && header->cmsg_level == SOL_SOCKET &&
                  header->cmsg_type == SCM_RIGHTS && header->cmsg_len == CMSG_LEN(sizeof(fd)) &&
                  !CMSG_NXTHDR(&message, header), "invalid native checkpoint request");
            memcpy(&fd, CMSG_DATA(header), sizeof(fd));
            int32_t status = irqfds_attached ? -EBUSY :
                native_x86_state_file(fd, kvm, vm, cpus, cpu_count, irqchip, pit_request, request[0] == 'a');
            close(fd);
            check(write(control, &status, sizeof(status)) == sizeof(status), "reply to native checkpoint request");
            continue;
        }
        check(!header, "unexpected native worker descriptor");
        if (received == 3 && request[0] == 'i') {
            check(parallel && request[1] == 0 && request[2] <= 1, "invalid native IRQFD transition");
            bool attach = request[2];
            int32_t status = 0;
            if (irqchip && attach != irqfds_attached) {
                status = set_irqfds(vm, irq_fds, attach);
                if (!status)
                    irqfds_attached = attach;
            }
            check(write(control, &status, sizeof(status)) == sizeof(status), "reply to native IRQFD transition");
            continue;
        }
        unsigned int id = request[1];
        int cpu = cpus[id];
        if (received == 2 + sizeof(registers) && request[0] == 'S') {
            memcpy(&registers, request + 2, sizeof(registers));
            check(ioctl(cpu, KVM_SET_REGS, &registers) == 0, "write host registers");
            check(write(control, "S", 1) == 1, "acknowledge host register write");
            continue;
        }
        if (received == 2 + sizeof(segments) && request[0] == 'P') {
            struct kvm_sregs setup;
            memcpy(&setup, request + 2, sizeof(setup));
            if (setup.gdt.limit == 31) {
                segments = setup;
            } else {
                check(ioctl(cpu, KVM_GET_SREGS, &segments) == 0, "read host protected-entry baseline");
                segments.cs = setup.cs;
                segments.ds = setup.ds;
                segments.es = setup.es;
                segments.fs = setup.fs;
                segments.gs = setup.gs;
                segments.ss = setup.ss;
                segments.gdt = setup.gdt;
                segments.cr0 |= setup.cr0;
                segments.cr3 = setup.cr3;
                segments.cr4 |= setup.cr4;
                segments.efer |= setup.efer;
            }
            check(ioctl(cpu, KVM_SET_SREGS, &segments) == 0, "configure host protected mode");
            check(write(control, "P", 1) == 1, "acknowledge host protected mode");
            continue;
        }
        if (received == 2 && request[0] == 'G') {
            check(ioctl(cpu, KVM_GET_REGS, &registers) == 0, "read host registers after exit");
            check(write(control, &registers, sizeof(registers)) == (ssize_t)sizeof(registers),
                  "return host registers to the parent");
            continue;
        }
        if (received == 2 && request[0] == 'X') {
            check(ioctl(cpu, KVM_GET_SREGS, &segments) == 0, "read host special registers after exit");
            check(write(control, &segments, sizeof(segments)) == (ssize_t)sizeof(segments),
                  "return host special registers to the parent");
            continue;
        }
        if (received == 2 && request[0] == 'H') {
            struct kvm_debugregs debug;

            check(ioctl(cpu, KVM_GET_DEBUGREGS, &debug) == 0, "read live host debug registers");
            check(write(control, &debug, sizeof(debug)) == sizeof(debug), "return the host debug registers");
            continue;
        }
        if (received == 2 + sizeof(struct kvm_debugregs) && request[0] == 'I') {
            struct kvm_debugregs debug;

            memcpy(&debug, request + 2, sizeof(debug));
            check(ioctl(cpu, KVM_SET_DEBUGREGS, &debug) == 0, "restore live host debug registers");
            check(write(control, "I", 1) == 1, "acknowledge the host debug registers");
            continue;
        }
        if ((received == 2 && request[0] == 'p') ||
            (received == 2 + sizeof(struct kvm_mp_state) && request[0] == 'q')) {
            struct {
                int32_t status;
                struct kvm_mp_state state;
            } reply = {0};
            bool write_state = request[0] == 'q';

            if (write_state)
                memcpy(&reply.state, request + 2, sizeof(reply.state));
            if (ioctl(cpu, write_state ? KVM_SET_MP_STATE : KVM_GET_MP_STATE, &reply.state) < 0)
                reply.status = -errno;
            check(write(control, &reply, sizeof(reply)) == sizeof(reply), "return the host MP state result");
            continue;
        }
        if (received == 2 && request[0] == 's') {
            struct kvm_xcrs xcrs = {0};

            check(ioctl(cpu, KVM_GET_XCRS, &xcrs) == 0, "read actual host XCRs");
            check(write(control, &xcrs, sizeof(xcrs)) == sizeof(xcrs), "return the host XCR state");
            continue;
        }
        if (received == 2 + sizeof(struct kvm_xcrs) && request[0] == 't') {
            struct kvm_xcrs xcrs;
            int32_t result = 0;

            memcpy(&xcrs, request + 2, sizeof(xcrs));
            if (ioctl(cpu, KVM_SET_XCRS, &xcrs) < 0)
                result = -errno;
            check(write(control, &result, sizeof(result)) == sizeof(result), "return the host XCR ioctl result");
            continue;
        }
        if (received == 2 && request[0] == 'u') {
            struct {
                int32_t status;
                struct kvm_xsave xsave;
            } reply = {0};

            if (ioctl(cpu, KVM_GET_XSAVE, &reply.xsave) < 0)
                reply.status = -errno;
            check(write(control, &reply, sizeof(reply)) == sizeof(reply), "return the host XSAVE query result");
            continue;
        }
        if (received == 2 + sizeof(struct kvm_xsave) && request[0] == 'v') {
            int capacity = ioctl(vm, KVM_CHECK_EXTENSION, KVM_CAP_XSAVE2);
            size_t bytes = PVKVM_XSAVE_BYTES;
            int32_t result = 0;

            if (capacity > PVKVM_XSAVE_BYTES)
                bytes = capacity;
            struct kvm_xsave *xsave = calloc(1, bytes);
            if (xsave) {
                memcpy(xsave, request + 2, PVKVM_XSAVE_BYTES);
                if (ioctl(cpu, KVM_SET_XSAVE, xsave) < 0)
                    result = -errno;
                free(xsave);
            } else {
                result = -ENOMEM;
            }
            check(write(control, &result, sizeof(result)) == sizeof(result), "return the host XSAVE ioctl result");
            continue;
        }
        if ((received == 2 && request[0] == 'e') ||
            (received == 2 + sizeof(struct kvm_vcpu_events) && request[0] == 'f')) {
            struct {
                int32_t status;
                struct kvm_vcpu_events events;
            } reply = {0};
            unsigned char image[sizeof(reply.status) + sizeof(reply.events)];
            bool write_state = request[0] == 'f';

            if (write_state)
                memcpy(&reply.events, request + 2, sizeof(reply.events));
            if (ioctl(cpu, write_state ? KVM_SET_VCPU_EVENTS : KVM_GET_VCPU_EVENTS, &reply.events) < 0)
                reply.status = -errno;
            memcpy(image, &reply.status, sizeof(reply.status));
            memcpy(image + sizeof(reply.status), &reply.events, sizeof(reply.events));
            check(write(control, image, sizeof(image)) == sizeof(image), "return the host vCPU event result");
            continue;
        }
        if ((received == 2 && request[0] == 'c') ||
            (received == 2 + sizeof(struct kvm_clock_data) && request[0] == 'd')) {
            struct kvm_clock_data clock = {0};
            int32_t status = 0;
            unsigned char image[sizeof(status) + sizeof(clock)];
            bool write_clock = request[0] == 'd';

            if (write_clock)
                memcpy(&clock, request + 2, sizeof(clock));
            if (ioctl(vm, write_clock ? KVM_SET_CLOCK : KVM_GET_CLOCK, &clock) < 0)
                status = -errno;
            memcpy(image, &status, sizeof(status));
            memcpy(image + sizeof(status), &clock, sizeof(clock));
            check(write(control, image, sizeof(image)) == sizeof(image), "return the host VM clock result");
            continue;
        }
        if (received == 2 + sizeof(struct kvm_irq_level) && request[0] == 'L') {
            struct kvm_irq_level irq;
            memcpy(&irq, request + 2, sizeof(irq));
            check(irqchip && irq.irq < PVKVM_GSI_COUNT && irq.level <= 1 &&
                  ioctl(vm, KVM_IRQ_LINE, &irq) == 0, "set a host IRQ line");
            check(write(control, "L", 1) == 1, "acknowledge host IRQ line state");
            continue;
        }
        if (received == 2 + sizeof(struct kvm_irqchip) && (request[0] == 'J' || request[0] == 'K')) {
            struct kvm_irqchip chip;
            bool write_state = request[0] == 'K';
            memcpy(&chip, request + 2, sizeof(chip));
            check(irqchip && chip.chip_id < KVM_NR_IRQCHIPS &&
                  ioctl(vm, write_state ? KVM_SET_IRQCHIP : KVM_GET_IRQCHIP, &chip) == 0,
                  "access the host irqchip state");
            if (write_state)
                check(write(control, "K", 1) == 1, "acknowledge host irqchip state");
            else
                check(write(control, &chip, sizeof(chip)) == sizeof(chip), "return host irqchip state");
            continue;
        }
        if (received == 2 && request[0] == 'T') {
            struct kvm_pit_state2 pit;

            check(pit_request && ioctl(vm, KVM_GET_PIT2, &pit) == 0, "read the live host PIT");
            check(write(control, &pit, sizeof(pit)) == sizeof(pit), "return the host PIT image");
            continue;
        }
        if (received == 2 + sizeof(struct kvm_pit_state2) && request[0] == 'Y') {
            struct kvm_pit_state2 pit;

            memcpy(&pit, request + 2, sizeof(pit));
            check(pit_request && ioctl(vm, KVM_SET_PIT2, &pit) == 0, "restore the live host PIT");
            check(write(control, "Y", 1) == 1, "acknowledge the host PIT image");
            continue;
        }
        if (received == 2 && request[0] == 'F') {
            check(ioctl(cpu, KVM_GET_FPU, &fpu) == 0, "read host floating-point registers");
            check(write(control, &fpu, sizeof(fpu)) == (ssize_t)sizeof(fpu), "return host floating-point state");
            continue;
        }
        if (received == 2 + sizeof(fpu) && request[0] == 'W') {
            memcpy(&fpu, request + 2, sizeof(fpu));
            check(ioctl(cpu, KVM_SET_FPU, &fpu) == 0, "write host floating-point registers");
            check(write(control, "W", 1) == 1, "acknowledge host floating-point write");
            continue;
        }
        if (received == 2 && request[0] == 'A') {
            check(ioctl(cpu, KVM_GET_LAPIC, &lapic) == 0, "read host LAPIC");
            check(write(control, &lapic, sizeof(lapic)) == sizeof(lapic), "return host LAPIC state");
            continue;
        }
        if (received == 2 + sizeof(lapic) && request[0] == 'B') {
            memcpy(&lapic, request + 2, sizeof(lapic));
            check(ioctl(cpu, KVM_SET_LAPIC, &lapic) == 0, "write host LAPIC");
            check(write(control, "B", 1) == 1, "acknowledge host LAPIC state");
            continue;
        }
        if (request[0] == 'M' || request[0] == 'N') {
            const size_t header = offsetof(struct pvkvm_msr_batch, entries);
            bool set = request[0] == 'N';
            check(received >= 2 + (ssize_t)header && received <= 2 + (ssize_t)sizeof(msrs),
                  "invalid host MSR request size");
            size_t payload = received - 2;
            memcpy(&msrs, request + 2, payload);
            check(msrs.count <= PVKVM_MSR_BATCH_MAX &&
                  payload == header + msrs.count * sizeof(msrs.entries[0]), "invalid host MSR batch");
            int processed = ioctl(cpu, set ? KVM_SET_MSRS : KVM_GET_MSRS, &msrs);
            check(processed >= 0 && (uint32_t)processed <= msrs.count, "access host MSR registers");
            msrs.count = processed;
            size_t response = header + (set ? 0 : msrs.count * sizeof(msrs.entries[0]));
            check(write(control, &msrs, response) == (ssize_t)response, "return host MSR batch result");
            continue;
        }
        if (request[0] == 'C') {
            const size_t header = offsetof(struct pvkvm_cpuid_table, entries);
            check(received >= 2 + (ssize_t)header && received <= (ssize_t)sizeof(request),
                  "invalid host CPUID request size");
            size_t payload = received - 2;
            memcpy(&cpuid, request + 2, payload);
            check(cpuid.count <= PVKVM_CPUID_MAX &&
                  payload == header + cpuid.count * sizeof(cpuid.entries[0]), "invalid host CPUID table");
            check(ioctl(cpu, KVM_SET_CPUID2, &cpuid) == 0, "configure host CPUID table");
            check(write(control, "C", 1) == 1, "acknowledge host CPUID table");
            continue;
        }
        if (parallel) {
            uint32_t sequence;
            check(received == 2 + sizeof(sequence) && request[0] == 'I', "invalid parallel run interrupt");
            memcpy(&sequence, request + 2, sizeof(sequence));
            check(sequence > 0 && sequence <= INT_MAX, "invalid parallel run sequence");
            errno = pthread_sigqueue(threads[id], SIGRTMIN, (union sigval){.sival_int = sequence});
            check(!errno, "interrupt the selected vCPU thread");
        } else {
            serve_cpu_request(&lanes[id], control, request, received);
        }
    }
    if (parallel) {
        for (unsigned int id = 0; id < cpu_count; id++) {
            shutdown(lanes[id].control, SHUT_RD);
            errno = pthread_sigqueue(threads[id], SIGRTMIN, (union sigval){.sival_int = 0});
            check(!errno || errno == ESRCH, "stop the native vCPU thread");
        }
        for (unsigned int id = 0; id < cpu_count; id++) {
            errno = pthread_join(threads[id], NULL);
            check(!errno, "join the native vCPU thread");
        }
    }
    return 0;
}
