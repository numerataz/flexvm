// Run real KVM clients inside the ordinary FlexVM agent, with no guest shell.
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int execute(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execv(argv[0], argv);
        perror(argv[0]);
        _exit(127);
    }
    int status;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "KVM workload failed: %s\n", argv[0]);
        return -1;
    }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char *const abi[] = {"/kvm-abi", NULL};
    if (execute(abi) < 0) return 1;
    puts("FLEXVM_SOFTWARE_KVM_API_PASSED");
    char *const firecracker[] = {"/firecracker", "--no-api", "--config-file", "/firecracker.json", NULL};
    if (execute(firecracker) < 0) return 1;
    puts("FLEXVM_SOFTWARE_KVM_FIRECRACKER_PASSED");
    return 0;
}
