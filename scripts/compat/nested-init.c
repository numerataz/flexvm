#define _GNU_SOURCE
// PID 1 in the inner VM: independent progress and a clean hypervisor shutdown.
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <sched.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <unistd.h>

#include "parent-kvm/firecracker-net.h"

static int check_network(void)
{
    int fd = test_datagram_socket(6);
    struct sockaddr_in peer = test_network_peer();
    char data[sizeof(FLEXVM_TEST_PACKET)];

    if (fd < 0 || configure_test_link(fd, "eth0", FLEXVM_TEST_GUEST) < 0 ||
        connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0)
        return -1;
    for (unsigned int attempt = 0; attempt < 2; attempt++) {
        if (send(fd, FLEXVM_TEST_PACKET, sizeof(data), 0) == sizeof(data) &&
            recv(fd, data, sizeof(data), 0) == sizeof(data) &&
            !memcmp(data, FLEXVM_TEST_PACKET, sizeof(data))) {
            close(fd);
            return 0;
        }
    }
    close(fd);
    return -1;
}

int main(void) {
    int console = open("/dev/console", O_RDWR);
    if (console < 0) return 1;
    for (int fd = 0; fd < 3; fd++) if (dup2(console, fd) < 0) return 1;
    if (console > 2) close(console);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("FLEXVM_SOFTWARE_INNER_BOOTED");
    int network = access("/firecracker-network", F_OK) == 0;
    int persistent_block = access("/firecracker-block", F_OK) == 0;
    if (network || persistent_block) {
        cpu_set_t online;
        if (sched_getaffinity(0, sizeof(online), &online) < 0)
            return 1;
        for (int id = 0; id < CPU_SETSIZE; id++) {
            if (CPU_ISSET(id, &online)) {
                cpu_set_t selected;
                CPU_ZERO(&selected);
                CPU_SET(id, &selected);
                if (sched_setaffinity(0, sizeof(selected), &selected) < 0 || sched_getcpu() != id)
                    return 1;
                printf("FLEXVM_SOFTWARE_INNER_CPU %d\n", id);
            }
        }
        if (sched_setaffinity(0, sizeof(online), &online) < 0)
            return 1;
        printf("FLEXVM_SOFTWARE_INNER_CPUS %d\n", CPU_COUNT(&online));
    }
    if (network) {
        if (check_network() < 0) {
            perror("inner Firecracker network");
            return 1;
        }
        puts("FLEXVM_SOFTWARE_INNER_NETWORK");
    }
    int checkpoint = access("/firecracker-checkpoint", F_OK) == 0;
    uint64_t nonce = 0;
    if (checkpoint && getrandom(&nonce, sizeof(nonce), 0) != sizeof(nonce))
        return 1;
    volatile uint64_t canary = nonce;
    int block = -1;
    _Alignas(4096) unsigned char sector[4096] = {0};
    if (persistent_block) {
        if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) < 0)
            return 1;
        block = open("/dev/vda", O_RDWR | O_DIRECT | O_CLOEXEC);
        if (block < 0 || pread(block, sector, sizeof(sector), 0) != sizeof(sector) || sector[0] != 'F') {
            perror("read nested virtio block marker");
            return 1;
        }
        memset(sector, 0, sizeof(sector));
        memcpy(sector, &nonce, sizeof(nonce));
        if (pwrite(block, sector, sizeof(sector), sizeof(sector)) != sizeof(sector) || fsync(block) < 0) {
            perror("write and flush nested virtio block canary");
            return 1;
        }
        printf("FLEXVM_X86_BLOCK_FLUSHED %016" PRIx64 "\n", canary);
    }
    for (unsigned i = 0; i < 3; i++) {
        if (checkpoint && i == 0) {
            printf("FLEXVM_SOFTWARE_INNER_CANARY %016" PRIx64 "\n", canary);
            sleep(5);
        }
        if (checkpoint && i == 1) {
            if (block >= 0) {
                uint64_t actual;
                if (pread(block, sector, sizeof(sector), sizeof(sector)) != sizeof(sector)) {
                    perror("read nested virtio block after restore");
                    return 1;
                }
                memcpy(&actual, sector, sizeof(actual));
                if (actual != canary) {
                    fprintf(stderr, "nested virtio block canary changed\n");
                    return 1;
                }
                close(block);
                printf("FLEXVM_X86_BLOCK_READ %016" PRIx64 "\n", actual);
            }
            printf("FLEXVM_SOFTWARE_INNER_RESTORED %016" PRIx64 "\n", canary);
        }
        printf("FLEXVM_SOFTWARE_INNER_TICK %u\n", i);
        if (i == 0 && access("/checkpoint-gate", F_OK) == 0) {
            puts("FLEXVM_SOFTWARE_INNER_WAITING");
            char token[2];
            for (unsigned n = 0; n < sizeof(token);) {
                ssize_t got = read(STDIN_FILENO, token + n, sizeof(token) - n);
                if (got < 0 && errno == EINTR) continue;
                if (got <= 0) return 1;
                n += (unsigned)got;
            }
            if (token[0] != 'C' || token[1] != '\n') return 1;
        }
        sleep(1);
    }
    puts("FLEXVM_SOFTWARE_INNER_COMPLETE");
    // Firecracker's x86 machine has no ACPI power-off device. Its supported
    // i8042 reset request exits the VMM; ARM uses PSCI system power-off.
#if defined(__x86_64__)
    int stop = RB_AUTOBOOT;
#else
    int stop = RB_POWER_OFF;
#endif
    if (reboot(stop) < 0) {
        perror("inner power off");
        for (;;) pause();
    }
    return 1;
}
