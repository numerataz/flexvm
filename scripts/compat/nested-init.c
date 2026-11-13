// PID 1 in the inner VM: independent progress and a clean hypervisor shutdown.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/reboot.h>
#include <unistd.h>

int main(void) {
    int console = open("/dev/console", O_RDWR);
    if (console < 0) return 1;
    for (int fd = 0; fd < 3; fd++) if (dup2(console, fd) < 0) return 1;
    if (console > 2) close(console);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("FLEXVM_SOFTWARE_INNER_BOOTED");
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
    if (reboot(RB_POWER_OFF) < 0) {
        perror("inner power off");
        for (;;) pause();
    }
    return 1;
}
