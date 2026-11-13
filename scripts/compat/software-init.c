// PID 1 for a software CPU boot test: real guest syscalls, timers, and shutdown.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <unistd.h>

static int execute(const char *program, char *const argv[]) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        execv(program, argv);
        _exit(127);
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

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
        char *const argv[] = {"/kvm-abi", NULL};
        if (execute(argv[0], argv) < 0) {
            puts("FLEXVM_SOFTWARE_GUEST_KVM_FAILED");
            for (;;) pause();
        }
    }
    if (access("/firecracker", F_OK) == 0) {
        char *const argv[] = {"/firecracker", "--no-api", "--config-file", "/firecracker.json", NULL};
        if (mount("proc", "/proc", "proc", 0, NULL) < 0 ||
            mount("sysfs", "/sys", "sysfs", 0, NULL) < 0 || execute(argv[0], argv) < 0) {
            puts("FLEXVM_SOFTWARE_GUEST_FIRECRACKER_FAILED");
            for (;;) pause();
        }
        puts("FLEXVM_SOFTWARE_GUEST_FIRECRACKER_PASSED");
    }
    puts("FLEXVM_SOFTWARE_GUEST_COMPLETE");
    if (reboot(RB_POWER_OFF) < 0) {
        perror("power off");
        for (;;) pause();
    }
    return 1;
}
