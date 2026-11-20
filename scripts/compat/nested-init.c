#define _GNU_SOURCE
// PID 1 in the inner VM: independent progress and a clean hypervisor shutdown.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sched.h>
#include <string.h>
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
    cpu_set_t online;
    if (sched_getaffinity(0, sizeof(online), &online) == 0)
        printf("FLEXVM_SOFTWARE_INNER_CPUS %d\n", CPU_COUNT(&online));
    if (access("/firecracker-network", F_OK) == 0) {
        if (check_network() < 0) {
            perror("inner Firecracker network");
            return 1;
        }
        puts("FLEXVM_SOFTWARE_INNER_NETWORK");
    }
    for (unsigned i = 0; i < 3; i++) {
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
