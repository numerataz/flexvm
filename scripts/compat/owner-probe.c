// Static OCI workload for the actual named software VM owner/control path.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && strcmp(argv[1], "flood") == 0) {
        char bytes[8192];
        memset(bytes, 'x', sizeof(bytes));
        for (;;) if (fwrite(bytes, 1, sizeof(bytes), stdout) != sizeof(bytes)) return 1;
    }
    if (argc == 1) {
        puts("OWNER_WORKLOAD_STARTED");
        while (access("/tmp/owner-finish", F_OK) != 0) usleep(10000);
        puts("OWNER_WORKLOAD_FINISHED");
        return 23;
    }
    if (strcmp(argv[1], "finish") == 0) {
        FILE *done = fopen("/tmp/owner-finish", "w");
        if (!done) return 1;
        return fclose(done) != 0;
    }
    if (strcmp(argv[1], "exec") == 0 && argc == 3) {
        char cwd[4096];
        if (!getcwd(cwd, sizeof(cwd))) return 1;
        printf("uid=%u gid=%u cwd=%s env=%s arg=%s\n", (unsigned)getuid(), (unsigned)getgid(), cwd,
               getenv("OWNER_TEST") ? getenv("OWNER_TEST") : "", argv[2]);
        fputs("OWNER_EXEC_STDERR\n", stderr);
        return 17;
    }
    return 2;
}
