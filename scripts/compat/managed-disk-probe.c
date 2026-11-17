#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3 || (strcmp(argv[1], "primary") != 0 && strcmp(argv[1], "secondary") != 0)) return 2;
    int first = strcmp(argv[1], "primary") == 0;
    const char *dev = first ? "/dev/vdb" : "/dev/vdc";
    const char *dirpath = first ? "/mnt/primary" : "/mnt/secondary";
    const char *file = first ? "/mnt/primary/data" : "/mnt/secondary/data";
    if ((mkdir("/mnt", 0700) < 0 && errno != EEXIST) || (mkdir(dirpath, 0700) < 0 && errno != EEXIST)) return 2;
    if (mount(dev, dirpath, "ext4", 0, NULL) < 0 && errno != EBUSY) {
        perror("mount");
        return 3;
    }
    if (strcmp(argv[2], "write") == 0 && argc == 4) {
        int fd = open(file, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0 || write(fd, argv[3], strlen(argv[3])) != (ssize_t)strlen(argv[3]) || fsync(fd) || close(fd)) {
            perror("write and sync");
            return 4;
        }
        int dir = open(dirpath, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
        if (dir < 0 || fsync(dir) || close(dir)) {
            perror("sync directory");
            return 4;
        }
    } else if (strcmp(argv[2], "read") == 0 && argc == 3) {
        int fd = open(file, O_RDONLY | O_CLOEXEC);
        char bytes[128];
        ssize_t length = fd < 0 ? -1 : read(fd, bytes, sizeof(bytes));
        if (length < 0 || write(STDOUT_FILENO, bytes, length) != length || close(fd)) {
            perror("read");
            return 5;
        }
    } else {
        return 2;
    }
    return 0;
}
