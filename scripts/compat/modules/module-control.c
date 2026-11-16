// Guest-only loader for the accelerated lifecycle fixture. Never run on the host.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int load(const char *name) {
    int fd = open(name, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror(name); return 1; }
    int result = syscall(SYS_finit_module, fd, "", 0);
    int error = errno;
    close(fd);
    if (result) { errno = error; perror(name); return 1; }
    return 0;
}

static int unload(const char *name) {
    if (syscall(SYS_delete_module, name, O_NONBLOCK)) { perror(name); return 1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "load")) {
        return load("/tmp/kmods/flexvm_test_state.ko") || load("/tmp/kmods/flexvm_test_device.ko");
    }
    if (!strcmp(argv[1], "unload")) {
        return unload("flexvm_test_device") || unload("flexvm_test_state");
    }
    if (!strcmp(argv[1], "busy")) {
        if (syscall(SYS_delete_module, "flexvm_test_state", O_NONBLOCK) < 0 && errno == EWOULDBLOCK) return 0;
        fputs("dependent module was not protected\n", stderr);
        return 1;
    }
    if (!strcmp(argv[1], "read")) {
        FILE *device = fopen("/dev/flexvm-module-test", "r");
        char text[128];
        if (!device || !fgets(text, sizeof(text), device)) return 1;
        fputs(text, stdout);
        return fclose(device) != 0;
    }
    return 2;
}
