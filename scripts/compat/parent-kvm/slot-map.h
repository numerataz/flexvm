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
#define FLEXVM_SLOT_MAX_PAGES 65536

/* A sealed table of little-endian uint64_t file offsets in guest GPA order. */
static void *flexvm_map_slot(int ram, int layout, size_t *bytes)
{
    const int ram_seals = F_SEAL_GROW | F_SEAL_SHRINK;
    const int layout_seals = ram_seals | F_SEAL_WRITE;
    struct stat ram_stat, layout_stat;

    int ram_flags = fcntl(ram, F_GET_SEALS);
    int layout_flags = fcntl(layout, F_GET_SEALS);
    if (ram_flags < 0 || layout_flags < 0 ||
        (ram_flags & ram_seals) != ram_seals ||
        (layout_flags & layout_seals) != layout_seals ||
        fstat(ram, &ram_stat) < 0 || fstat(layout, &layout_stat) < 0 ||
        ram_stat.st_size < FLEXVM_SLOT_PAGE_SIZE || layout_stat.st_size <= 0 ||
        (uint64_t)layout_stat.st_size > FLEXVM_SLOT_MAX_PAGES * sizeof(uint64_t) ||
        layout_stat.st_size % sizeof(uint64_t)) {
        errno = EINVAL;
        return MAP_FAILED;
    }

    size_t table_bytes = layout_stat.st_size;
    uint64_t *table = mmap(NULL, table_bytes, PROT_READ, MAP_PRIVATE, layout, 0);
    if (table == MAP_FAILED) {
        return MAP_FAILED;
    }
    size_t pages = table_bytes / sizeof(uint64_t);
    size_t length = pages * FLEXVM_SLOT_PAGE_SIZE;
    unsigned char *address = MAP_FAILED;
    int error;
    for (size_t page = 0; page < pages; page++) {
        uint64_t offset = le64toh(table[page]);
        if (offset % FLEXVM_SLOT_PAGE_SIZE ||
            offset > (uint64_t)ram_stat.st_size - FLEXVM_SLOT_PAGE_SIZE) {
            errno = EINVAL;
            goto out;
        }
    }

    address = mmap(NULL, length, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (address == MAP_FAILED) {
        goto out;
    }
    for (size_t begin = 0; begin < pages;) {
        size_t end = begin + 1;
        while (end < pages && le64toh(table[end]) == le64toh(table[end - 1]) + FLEXVM_SLOT_PAGE_SIZE) {
            end++;
        }
        void *destination = address + begin * FLEXVM_SLOT_PAGE_SIZE;
        if (mmap(destination, (end - begin) * FLEXVM_SLOT_PAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_FIXED | MAP_SHARED, ram, le64toh(table[begin])) == MAP_FAILED) {
            error = errno;
            munmap(address, length);
            address = MAP_FAILED;
            errno = error;
            goto out;
        }
        begin = end;
    }
    *bytes = length;
out:
    error = errno;
    munmap(table, table_bytes);
    errno = error;
    return address;
}

#endif
