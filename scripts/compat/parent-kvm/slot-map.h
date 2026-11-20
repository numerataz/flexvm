/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FLEXVM_SLOT_MAP_H
#define FLEXVM_SLOT_MAP_H

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define FLEXVM_SLOT_PAGE_SIZE 4096
#define FLEXVM_SLOT_MAX_PAGES 128

/* A sealed table of little-endian uint64_t file offsets in guest GPA order. */
static void *flexvm_map_slot(int ram, int layout, size_t *bytes)
{
    const int ram_seals = F_SEAL_GROW | F_SEAL_SHRINK;
    const int layout_seals = ram_seals | F_SEAL_WRITE;
    struct stat ram_stat, layout_stat;
    uint64_t offsets[FLEXVM_SLOT_MAX_PAGES];

    int ram_flags = fcntl(ram, F_GET_SEALS);
    int layout_flags = fcntl(layout, F_GET_SEALS);
    if (ram_flags < 0 || layout_flags < 0 ||
        (ram_flags & ram_seals) != ram_seals ||
        (layout_flags & layout_seals) != layout_seals ||
        fstat(ram, &ram_stat) < 0 || fstat(layout, &layout_stat) < 0 ||
        ram_stat.st_size < FLEXVM_SLOT_PAGE_SIZE || layout_stat.st_size <= 0 ||
        (uint64_t)layout_stat.st_size > sizeof(offsets) || layout_stat.st_size % sizeof(uint64_t)) {
        errno = EINVAL;
        return MAP_FAILED;
    }

    if (pread(layout, offsets, layout_stat.st_size, 0) != layout_stat.st_size) {
        errno = EIO;
        return MAP_FAILED;
    }
    size_t pages = layout_stat.st_size / sizeof(uint64_t);
    for (size_t page = 0; page < pages; page++) {
        offsets[page] = le64toh(offsets[page]);
        if (offsets[page] % FLEXVM_SLOT_PAGE_SIZE ||
            offsets[page] > (uint64_t)ram_stat.st_size - FLEXVM_SLOT_PAGE_SIZE) {
            errno = EINVAL;
            return MAP_FAILED;
        }
    }

    size_t length = pages * FLEXVM_SLOT_PAGE_SIZE;
    unsigned char *address = mmap(NULL, length, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (address == MAP_FAILED) {
        return MAP_FAILED;
    }
    for (size_t begin = 0; begin < pages;) {
        size_t end = begin + 1;
        while (end < pages && offsets[end] == offsets[end - 1] + FLEXVM_SLOT_PAGE_SIZE) {
            end++;
        }
        void *destination = address + begin * FLEXVM_SLOT_PAGE_SIZE;
        if (mmap(destination, (end - begin) * FLEXVM_SLOT_PAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_FIXED | MAP_SHARED, ram, offsets[begin]) == MAP_FAILED) {
            int error = errno;
            munmap(address, length);
            errno = error;
            return MAP_FAILED;
        }
        begin = end;
    }
    *bytes = length;
    return address;
}

#endif
