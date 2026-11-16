// RAM/process continuity through a real FlexVM agent cold restore.
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *path = "/tmp/state-observation";
    if (argc == 2 && strcmp(argv[1], "status") == 0) {
        FILE *f = fopen(path, "r");
        if (!f) return 1;
        char line[512];
        if (!fgets(line, sizeof(line), f)) return 2;
        fputs(line, stdout);
        return fclose(f) != 0;
    }
    if (argc != 1) return 2;
    volatile unsigned char ram[4096];
    if (getrandom((void *)ram, sizeof(ram), 0) != sizeof(ram)) return 3;
    FILE *stat = fopen("/proc/self/stat", "r");
    char identity[4096];
    if (!stat || !fgets(identity, sizeof(identity), stat)) return 4;
    fclose(stat);
    char *field = strrchr(identity, ')');
    if (!field) return 5;
    field += 2;
    for (int n = 3; n < 22; n++) {
        field = strchr(field, ' ');
        if (!field) return 6;
        field++;
    }
    uint64_t start = strtoull(field, NULL, 10);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("STATE_WORKLOAD_BOOT");
    for (uint64_t count = 0;;count++) {
        uint64_t hash = UINT64_C(14695981039346656037);
        for (size_t i = 0; i < sizeof(ram); i++) hash = (hash ^ ram[i]) * UINT64_C(1099511628211);
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 7;
        FILE *f = fopen("/tmp/state-observation.next", "w");
        if (!f) return 8;
        fprintf(f, "%u %" PRIu64 " %" PRIu64 " %" PRIu64 " %lld\n", (unsigned)getpid(), start, hash, count,
                (long long)now.tv_sec * 1000000000LL + now.tv_nsec);
        if (fclose(f) != 0 || rename("/tmp/state-observation.next", path) != 0) return 9;
        printf("STATE_TICK %" PRIu64 "\n", count);
        usleep(100000);
    }
}
