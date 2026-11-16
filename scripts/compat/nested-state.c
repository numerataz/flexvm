// One fixture binary: PID 1 inside Firecracker, its outer supervisor, and status/control clients.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *observation = "/tmp/state-observation";
static const char *command = "/tmp/nested-command";
static _Atomic unsigned inner_mode;

static uint64_t monotonic(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) exit(7);
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static uint64_t start_time(pid_t pid) {
    char path[64], text[4096];
    snprintf(path, sizeof(path), "/proc/%u/stat", (unsigned)pid);
    FILE *file = fopen(path, "r");
    if (!file) return UINT64_MAX;
    char *got = fgets(text, sizeof(text), file);
    fclose(file);
    if (!got) return UINT64_MAX;
    char *field = strrchr(text, ')');
    if (!field) return UINT64_MAX;
    field += 2;
    for (int i = 3; i < 22; i++) {
        field = strchr(field, ' ');
        if (!field) return UINT64_MAX;
        field++;
    }
    return strtoull(field, NULL, 10);
}

static uint64_t hash(const volatile unsigned char *ram) {
    uint64_t result = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < 4096; i++) result = (result ^ ram[i]) * UINT64_C(1099511628211);
    return result;
}

static int random_ram(volatile unsigned char *ram) {
    size_t offset = 0;
    while (offset < 4096) {
        ssize_t got = getrandom((void *)(ram + offset), 4096 - offset, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        offset += (size_t)got;
    }
    return 0;
}

static void *inner_commands(void *unused) {
    (void)unused;
    char line[64];
    while (fgets(line, sizeof(line), stdin)) {
        if (strcmp(line, "TIMER\n") == 0) atomic_store(&inner_mode, 0);
        else if (strcmp(line, "SPIN\n") == 0) atomic_store(&inner_mode, 1);
        else if (strcmp(line, "QUIT\n") == 0) atomic_store(&inner_mode, 2);
    }
    return NULL;
}

static int inner(void) {
    int console = open("/dev/console", O_RDWR);
    if (console < 0) return 1;
    for (int fd = 0; fd < 3; fd++) if (dup2(console, fd) < 0) return 1;
    if (console > 2) close(console);
    setvbuf(stdout, NULL, _IONBF, 0);
    if (mkdir("/proc", 0555) != 0 && errno != EEXIST) return 2;
    if (mount("proc", "/proc", "proc", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL) != 0 && errno != EBUSY) return 2;
    // The outer guest has initialized entropy. A one-shot seed also makes a
    // reboot fail: the supervisor never answers a second READY handshake.
    puts("NESTED_INNER_READY");
    char line[64];
    uint32_t seed;
    if (!fgets(line, sizeof(line), stdin) || sscanf(line, "SEED %" SCNx32, &seed) != 1) return 3;
    volatile unsigned char ram[4096];
    uint32_t random = seed ? seed : 1;
    for (size_t i = 0; i < sizeof(ram); i++) {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        ram[i] = (unsigned char)random;
    }
    uint64_t start = start_time(getpid());
    pthread_t reader;
    if (start == UINT64_MAX || pthread_create(&reader, NULL, inner_commands, NULL) != 0) return 4;
    puts("NESTED_INNER_BOOT");
    volatile uint64_t work = 0;
    for (uint64_t count = 0;; count++) {
        unsigned mode = atomic_load(&inner_mode);
        if (mode == 2) break;
        uint64_t now = monotonic();
        printf("NESTED_STATE %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %u %" PRIu64 "\n",
               (unsigned)getpid(), start, hash(ram), count, now, mode, work);
        uint64_t until = now + UINT64_C(100000000);
        if (mode == 0) {
            struct timespec wake = {.tv_sec = (time_t)(until / UINT64_C(1000000000)), .tv_nsec = (long)(until % UINT64_C(1000000000))};
            int error;
            do { error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &wake, NULL); } while (error == EINTR);
            if (error) return 5;
        } else {
            while (monotonic() < until) for (unsigned i = 0; i < 1024; i++) work++;
        }
    }
    puts("NESTED_INNER_COMPLETE");
#if defined(__x86_64__)
    int stop = RB_AUTOBOOT;
#else
    int stop = RB_POWER_OFF;
#endif
    if (reboot(stop) != 0) return 6;
    return 1;
}

static int client(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "mode") == 0) {
        const char *mode;
        if (strcmp(argv[2], "timer") == 0) mode = "TIMER";
        else if (strcmp(argv[2], "spin") == 0) mode = "SPIN";
        else if (strcmp(argv[2], "quit") == 0) mode = "QUIT";
        else return 2;
        FILE *file = fopen("/tmp/nested-command.next", "w");
        if (!file) return 1;
        int written = fprintf(file, "%s\n", mode);
        if (fclose(file) != 0 || written < 0 || rename("/tmp/nested-command.next", command) != 0) return 1;
        return 0;
    }
    if (argc != 2 || (strcmp(argv[1], "status") != 0 && strcmp(argv[1], "status-full") != 0)) return 2;
    FILE *file = fopen(observation, "r");
    if (!file) return 1;
    uint64_t value[12];
    for (size_t i = 0; i < 12; i++) {
        if (fscanf(file, "%" SCNu64, &value[i]) != 1) { fclose(file); return 1; }
    }
    fclose(file);
    if (strcmp(argv[1], "status-full") == 0) {
        for (size_t i = 0; i < 12; i++) printf("%s%" PRIu64, i ? " " : "", value[i]);
        puts("");
    } else {
        // The standard lifecycle probe checks these three stable identities,
        // plus an inner counter and clock that must advance after restore.
        printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
               value[0], value[1], value[2] ^ value[7] ^ (value[3] << 32) ^ value[4], value[8], value[9]);
    }
    return 0;
}

static int outer(void) {
    volatile unsigned char ram[4096];
    if (random_ram(ram) != 0) return 1;
    uint64_t start = start_time(getpid());
    uint32_t seed = 0;
    for (size_t i = 0; i < sizeof(seed); i++) seed = (seed << 8) | ram[i];
    int input[2], output[2];
    if (start == UINT64_MAX || pipe2(input, O_CLOEXEC) != 0 || pipe2(output, O_CLOEXEC) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        if (dup2(input[0], STDIN_FILENO) < 0 || dup2(output[1], STDOUT_FILENO) < 0 || dup2(output[1], STDERR_FILENO) < 0) _exit(126);
        close(input[0]); close(input[1]); close(output[0]); close(output[1]);
        execl("/firecracker", "firecracker", "--no-api", "--config-file", "/firecracker.json", (char *)NULL);
        _exit(127);
    }
    close(input[0]); close(output[1]);
    uint64_t child_start = start_time(child);
    int result = 1, status = 0;
    unsigned ready = 0, boots = 0;
    char pending[16384];
    size_t used = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("STATE_WORKLOAD_BOOT");
    for (;;) {
        FILE *request = fopen(command, "r");
        if (request) {
            char mode[32];
            int have = fgets(mode, sizeof(mode), request) != NULL;
            fclose(request);
            if (have && (strcmp(mode, "SPIN\n") == 0 || strcmp(mode, "TIMER\n") == 0 || strcmp(mode, "QUIT\n") == 0)) {
                if (write(input[1], mode, strlen(mode)) != (ssize_t)strlen(mode) || unlink(command) != 0) break;
            } else break;
        }
        struct pollfd waiting = {.fd = output[0], .events = POLLIN};
        int polled = poll(&waiting, 1, 20);
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0) break;
        if (!polled) continue;
        ssize_t got = read(output[0], pending + used, sizeof(pending) - used - 1);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            if (waitpid(child, &status, 0) == child) {
                child = -1;
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && boots == 1) result = 23;
            }
            break;
        }
        used += (size_t)got;
        pending[used] = 0;
        char *line = pending, *end;
        while ((end = strchr(line, '\n'))) {
            *end = 0;
            if (strcmp(line, "NESTED_INNER_READY\r") == 0 || strcmp(line, "NESTED_INNER_READY") == 0) {
                if (ready++) goto finished;
                char token[32];
                int length = snprintf(token, sizeof(token), "SEED %08" PRIx32 "\n", seed);
                if (write(input[1], token, (size_t)length) != length) goto finished;
            }
            if (strcmp(line, "NESTED_INNER_BOOT\r") == 0 || strcmp(line, "NESTED_INNER_BOOT") == 0) if (++boots != 1) goto finished;
            uint64_t inner_pid, inner_start, inner_hash, count, now, work;
            unsigned mode;
            if (sscanf(line, "NESTED_STATE %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %u %" SCNu64,
                       &inner_pid, &inner_start, &inner_hash, &count, &now, &mode, &work) == 7) {
                FILE *file = fopen("/tmp/state-observation.next", "w");
                if (!file || child_start == UINT64_MAX) goto finished;
                int written = fprintf(file, "%u %" PRIu64 " %" PRIu64 " %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %u %" PRIu64 "\n",
                                      (unsigned)getpid(), start, hash(ram), (unsigned)child, child_start, inner_pid, inner_start, inner_hash, count, now, mode, work);
                if (fclose(file) != 0 || written < 0 || rename("/tmp/state-observation.next", observation) != 0) goto finished;
                printf("STATE_TICK %" PRIu64 "\n", count);
            } else printf("%s\n", line);
            line = end + 1;
        }
        used -= (size_t)(line - pending);
        memmove(pending, line, used);
        if (used == sizeof(pending) - 1) break;
    }
finished:
    close(input[1]); close(output[0]);
    if (child > 0) { kill(child, SIGKILL); while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} }
    return result;
}

int main(int argc, char **argv) {
    if (getpid() == 1) return inner();
    return argc > 1 ? client(argc, argv) : outer();
}
