# Managed raw volume catalog

The catalog creates retained sparse raw storage independently of VM lifetime.
Named software VMs can attach a volume as a writable virtio-blk data disk.
Automatic cross-host disk transfer is tracked in #1329.

```sh
flexvm volume create database --size 1073741824
flexvm volume clone database database-copy
flexvm volume ls
flexvm volume inspect database
flexvm volume rm database
```

Sizes are byte counts, aligned to 512 bytes, from 512 bytes to 8 TiB. JSON output
separates `capacity_bytes` from `allocated_bytes`; a newly created sparse volume
can have no allocated data blocks. Every volume has a random immutable `id`.
Names are aliases; inspect, remove and clone source selection accept either the
full ID or the name.
The catalog is private to the user owning the selected `--state` directory; its
parent must already exist. No VMM, guest kernel or host `/dev/kvm` is required.

Creation synchronizes the raw file, metadata, staging directory and catalog
publication. Interrupted creation stays unpublished. Removal first acquires an
exclusive disk lock and publishes a synchronized deletion tombstone. An inherited
writer lock keeps removal refused after the original descriptor closes. Catalog
mutations finish recognized interrupted creations/deletions; unknown members or
formats are preserved and cause an error. Versioned `.creating-v1-` and
`.deleting-v1-` prefixes identify the recovery protocol and must change if that
protocol changes. Catalog operations never follow member symlinks or accept
hardlinked backing files.

Catalog operation locks are explicitly released when an operation ends, even
if an unrelated child has inherited its descriptor before exec. Raw disk writer
leases remain separate and survive until their inherited descriptors close.

A named QEMU software VM opens its volumes through the catalog and passes the
writer descriptors to its emulator. Cloning, deleting and opening the same
volume for another VM require that writer lease to be free.

## Independent clones

`volume clone SOURCE NAME` creates a new volume ID and independent backing inode
with the same logical capacity and contents. Later writes to either volume do
not change the other. The source must be unused: cloning acquires its exclusive
disk lock, including refusal while an engine/helper inherits a writer lease.
The catalog mutation lock stays held until copying and publication finish.

On supporting filesystems, Linux
[`FICLONE`](https://man7.org/linux/man-pages/man2/FICLONE.2const.html) shares storage
until a write requires a private copy. Otherwise FlexVM copies sparse data extents
with a bounded buffer. Zero buffers are skipped when the filesystem does not
report holes. Unsupported clone/extent operations use the fallback; other I/O
errors fail the unpublished transaction. Incomplete copies are recovered through
the same versioned creation protocol as ordinary volumes.

These are mutable storage clones of unused volumes. Coherent VM RAM/disk
checkpoints, sealed generation retention and automatic migration remain part of
#1329. The clone primitive is tracked in #1445.

`scripts/compat/volume-clone.py` exercises the actual CLI in its own private
mount namespace with host KVM/vsock masked and file/ioctl traces retained.
CI runs extent copying and forced unsupported-operation fallback on both
architectures, plus a temporary Btrfs reflink check on x86_64.


## Attach a disk to a software VM

```sh
flexvm volume create database --size 1073741824
flexvm software --name db --kernel /path/to/vmlinux --disk database IMAGE
```

Use additional `--disk` flags to attach more data disks in order. A new
volume is a raw block device that the guest can format and mount. Its data
persists independently of the guest's RAM and VM lifetime.

When a named VM stops, FlexVM drains QEMU's block I/O and records a sealed
copy of each managed disk with the RAM and device state. Local start acquires
the original disk's writer lease and verifies its bytes against that checkpoint
before running the guest. Changing the catalog volume while the VM is stopped
causes restore to fail rather than combine saved RAM with newer disk contents.
