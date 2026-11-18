/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <unistd.h>

static void check(int ok, const char *why)
{
    if (ok) return;
    perror(why);
    _exit(1);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    check(mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) == 0, "mount devtmpfs");
    cpu_set_t cpus;
    check(sched_getaffinity(0, sizeof(cpus), &cpus) == 0 && CPU_COUNT(&cpus) == FLEXVM_ARM_TEST_CPUS, "enumerate ARM CPUs");
    for (unsigned int cpu = 0; cpu < FLEXVM_ARM_TEST_CPUS; cpu++) {
        cpu_set_t selected;
        CPU_ZERO(&selected);
        CPU_SET(cpu, &selected);
        check(sched_setaffinity(0, sizeof(selected), &selected) == 0 && sched_getcpu() == (int)cpu, "run ARM CPU");
        printf("FLEXVM_ARM_INNER_CPU %u\n", cpu);
    }
    int block = open("/dev/vda", O_RDWR | O_DIRECT | O_CLOEXEC);
    check(block >= 0, "open virtio block device");
    _Alignas(4096) char data[4096];
    const char initial[] = "ARM outer persistent marker";
    const char written[] = "ARM inner completed block write";
    check(pread(block, data, sizeof(data), 0) == sizeof(data) &&
          memcmp(data, initial, sizeof(initial)) == 0, "read virtio block marker");
    memset(data, 0, sizeof(data));
    memcpy(data, written, sizeof(written));
    check(pwrite(block, data, sizeof(data), 4096) == sizeof(data) && fsync(block) == 0, "write and flush virtio block marker");
    memset(data, 0, sizeof(data));
    check(pread(block, data, sizeof(data), 4096) == sizeof(data) &&
          memcmp(data, written, sizeof(written)) == 0, "read back written virtio block marker");
    close(block);
    puts("PASS ARM Firecracker virtio block read, write and flush");
#ifdef FLEXVM_ARM_TEST_CHECKPOINT
    puts("ARM Firecracker checkpoint window");
    sleep(5);
    puts("PASS ARM Firecracker resumed after checkpoint freeze");
#endif
    sleep(1);
    puts("PASS ARM Firecracker architected timer");
    reboot(RB_POWER_OFF);
    return 1;
}
