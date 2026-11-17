# Managed raw volume catalog

The catalog creates retained sparse raw storage independently of VM lifetime.
VM attachment, filesystem formatting, disk checkpoints and automatic disk
migration are still being implemented in #1329. These commands manage unattached
storage; creating a volume does not yet add a disk to a VM.

```sh
flexvm volume create database --size 1073741824
flexvm volume ls
flexvm volume inspect database
flexvm volume rm database
```

Sizes are byte counts, aligned to 512 bytes, from 512 bytes to 8 TiB. JSON output
separates `capacity_bytes` from `allocated_bytes`; a newly created sparse volume
can have no allocated data blocks. Every volume has a random immutable `id`.
Names are aliases, and inspect/remove accept either the full ID or the name.
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

This lock is one prerequisite for future VM attachment. Durable migration
ownership, checkpoint references and the engine's inherited-descriptor lifecycle
must also be integrated before attached disks can use this catalog. The full
storage design is in PR #1436; catalog implementation is tracked in #1437.
