// PID 1 for a software CPU boot test: real guest syscalls, timers, and shutdown.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/reboot.h>
#include <sys/wait.h>
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
    if (access("/kvm-abi", F_OK) == 0) {
        pid_t child = fork();
        if (child == 0) {
            execl("/kvm-abi", "/kvm-abi", (char *)NULL);
            _exit(127);
        }
        int status = 0;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        if (child < 0 || waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            puts("FLEXVM_SOFTWARE_GUEST_KVM_FAILED");
            for (;;) pause();
        }
    }
    puts("FLEXVM_SOFTWARE_GUEST_COMPLETE");
    if (reboot(RB_POWER_OFF) < 0) {
        perror("power off");
        for (;;) pause();
    }
    return 1;
}
