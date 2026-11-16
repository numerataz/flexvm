// Test-only syscall faults at checkpoint publication, before parent fsync.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int fsync(int fd) {
    int (*next)(int) = dlsym(RTLD_NEXT, "fsync");
    if (!next) { errno = ENOSYS; return -1; }
    const char *marker = getenv("FLEXVM_TEST_FAIL_PARENT_SYNC");
    const char *crash = getenv("FLEXVM_TEST_KILL_PARENT_SYNC");
    if (marker || crash) {
        char link[64], path[PATH_MAX];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t length = readlink(link, path, sizeof(path) - 1);
        const char suffix[] = "/state/suspended";
        if (length >= (ssize_t)(sizeof(suffix) - 1)) {
            path[length] = 0;
            if (strcmp(path + length - (sizeof(suffix) - 1), suffix) == 0) {
                if (crash && unlink(crash) == 0) {
                    kill(getpid(), SIGKILL);
                    _exit(127);
                }
                if (marker && unlink(marker) == 0) {
                    errno = EIO;
                    return -1;
                }
            }
        }
    }
    return next(fd);
}
