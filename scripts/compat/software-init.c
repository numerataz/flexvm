// PID 1 for a software CPU boot test: real guest syscalls, timers, and shutdown.
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
    puts("FLEXVM_SOFTWARE_GUEST_BOOTED");
    for (unsigned i = 0; i < 3; i++) {
        printf("FLEXVM_SOFTWARE_GUEST_TICK %u\n", i);
        sleep(1);
    }
    puts("FLEXVM_SOFTWARE_GUEST_COMPLETE");
    if (reboot(RB_POWER_OFF) < 0) {
        perror("power off");
        for (;;) pause();
    }
    return 1;
}
