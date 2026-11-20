# Durable guest disks: implementation contract

This is the execution design for [#1329](https://github.com/numerataz/flexvm/issues/1329).
It describes work still to implement. Disks move with a migrating VM; shared
storage is not required. The current RAM-backed root and its lifecycle remain
the default until a disk-backed root is implemented and verified.

## Storage and ownership

A managed volume has an immutable random identifier, logical capacity and
versioned metadata in a private host-owned catalog. Human names are aliases.
The first format is a sparse raw image. Capacity, allocated storage and retained
checkpoint generations must be reported separately from guest RAM.

A writable attachment requires an exclusive lease for the volume's current
head. The VMM inherits the lease, so owner-process death cannot permit another
writer while the engine remains alive. Durable ownership records supplement
process locks: a retired migration source cannot regain authority merely by
restarting. Read-only attachments select sealed generations. Unknown ownership
or incomplete transactions remain fenced.

Volume lifetime is independent of VM lifetime. VM removal releases its
attachment but does not delete a user-created volume. Volume removal refuses
live attachments and generations retained by checkpoints or unresolved transfers.
Host paths in guest state never select catalog files.

Disk-enabled native VMs bypass pre-spawned standby engines. Acquire their leases
before spawning and add explicit lease-FD inheritance to the native spawn path.
Both backends spawn from a long-lived owner thread or use an explicit lifetime
monitor: parent-death signals are tied to the spawning thread and are insufficient
as the sole ownership mechanism. Persist the engine PID/start/boot identity and
require both released leases and proven engine retirement before regranting a head.

## Device integration

QEMU gets an explicitly configured virtio block device for every declared slot.
Commands are constructed locally from verified catalog objects. A checkpoint's
command line is never executed. Device identity, serial, capacity, sector format
and slot ordering are part of the execution profile and checkpoint binding.
Separate host catalog IDs from guest attachment serials. Normalize runtime FD
paths to logical disk slots in canonical profiles; never persist a transient
`/proc/.../fd/N` value as the execution contract.

Native Firecracker currently restores a prepared template with a fixed device
layout. Its default confinement policy rejects every block device. Adding a
path override alone is therefore insufficient. The native prototype must first
provide a trusted disk-enabled boot/layout and a constrained restore API. A cold
boot for disk-enabled VMs is acceptable initially; the existing shared-template
fast path remains available to diskless VMs.

The expected native device layout must come from locally constructed trusted
configuration, not a device-reference file supplied by an untrusted checkpoint.
Restore must match declared disk slots and geometry and open only the caller's
selected backing objects. Missing, extra, reordered or forged devices and
arbitrary host paths remain errors before resource opening. Changing the blanket
block rejection without these checks is not an implementation.

Disks appear before the guest's first partition scan on cold boot. Stable device
serials and filesystem UUIDs avoid reliance on backend-specific `/dev/vdX` names.
A writable root on a native filesystem is a later consumer of this same disk
path, and a prerequisite for ordinary reboot retaining package/root changes.
Its kernel command line must omit pmem-only DAX flags and select the writable
block root. Ordinary reboot needs explicit reset classification and a supervised
cold restart against the same disks, retaining owner leases throughout. Current
`reboot=k`/`-no-reboot` exit paths must not become accidental successful poweroff
or silently discard root changes.

## Checkpoints and forks

At the operation barrier, close command admission, quiesce the guest, pause CPUs,
drain device I/O and flush backing files. Capture RAM/device state and immutable
disk images at that same boundary. Use reflink where supported, otherwise a
bounded sparse copy; never hard-link an immutable checkpoint to a mutable head.
Hash the sealed generation after a fast snapshot, allowing source resume only
once RAM and every disk are frozen consistently. A sparse-copy fallback stays
within the pause boundary. Budget copy, hash and flush work with one operation
deadline scaled by bytes actually copied and logical bytes hashed; the fixed
VMM request timeout is not a large-disk operation deadline. Synchronize all
artifacts and their parent directory before atomic publication.
A failed capture preserves the prior committed checkpoint and source authority.

Suspend/start retains the same volume identities and requires the recorded disk
generations. Restore/fork of a checkpoint creates separate writable heads from
its immutable generations by default. It must not silently rewind an existing
named volume. Guest-visible device identity remains consistent with the saved
VM even when the host creates separate catalog identities for a fork.

The initial implementation may copy complete disk generations for incremental
RAM checkpoints. Runtime I/O and snapshot-copy performance are measured separately;
future delta transfer cannot weaken the consistency boundary.

## Migration transaction

Use explicitly configured authenticated host identities and extend the lifecycle
fencing model; signed software transfer receipts are a requirement, not an
already implemented software migration feature.
The transaction binds VM identity, RAM/device artifacts, attachment slots, disk
identifiers/generations, capacities and content digests into one manifest.

1. Freeze a coherent source generation while retaining its exclusive leases.
2. Transfer every referenced disk into private destination staging, enforcing
   aggregate size limits, digest/geometry checks and local file confinement.
3. Prepare the destination paused with the exact verified bindings, without
   granting CPU or write ownership.
4. Durably retire the source generation and reap its engine before issuing a
   retirement receipt. Retain a recovery copy until destination commitment.
5. Commit destination CPU and disk authority together before guest execution.
   A lost acknowledgment never allows unilateral source resume.

Rollback before retirement may resume the source. Recovery after retirement
requires a durable, authenticated destination abort/retirement acknowledgment
and a fresh generation. A timeout is not evidence that another writer is dead.
Crash recovery and garbage collection preserve unresolved transaction artifacts.
Acquire a multi-disk lease set in stable order and reserve all heads before
committing any authority transition. One durable commit record binds VM and disk
authority. An ambiguously transmitted pause/resume/load command is not permission
to release leases: reconcile state within a deadline, otherwise fence and reap
the engine while retaining its durable ownership. After destination grant, even
an uncertain resume cannot authorize source recovery.

Generation publication and deletion use synchronized staging and tombstones.
GC checks checkpoint, suspended-VM and transaction references under the catalog
lock; unresolved generations remain charged to storage accounting.

Software cross-host migration is currently unavailable. Durable-disk completion
must include its transfer path as well as the native path; local software
checkpoint success alone does not complete automatic migration support.

## Implementation and verification order

1. Prototype native cold disk attachment and constrained restore; retain and
   extend forged-device/path regression cases before exposing a disk API.
2. Implement the managed catalog, protected leases and both backend attachment
   paths, with a usable create/inspect/remove and VM attachment interface.
3. Add immutable disk generations to checkpoint, suspend/start and restore/fork.
4. Integrate automatic transfer and joint CPU/disk authority on both backends.
5. Add native writable-root boot, ordinary reboot and filesystem-backed runtime
   acceptance, alongside the current default RAM-root mode.

Each stage needs actual filesystem workloads. Acceptance includes ext4 and
SQLite WAL commits through VM/owner crashes, repeated suspend/start, fork
isolation, restart after VM removal using the retained volume, and migration
between separate host stores. Inject failure before and after publication,
retirement, transfer and destination grant. Verify that every outcome preserves
exactly one writer and the matching RAM/disk generation, including after restart.
Run software tests with host virtualization unavailable, native tests with KVM,
and request Agy review before merging implementation changes.

## Current foundation

`firecracker/0009-stable-block-serial.patch` adds an optional 1–20 byte ASCII
virtio block serial. Configured serials survive replacing the host backing inode
and device-state serialization; absent serials retain Firecracker's legacy
identity behavior. The API rejects serials on vhost-user drives. The existing
FlexVM block-device restore rejection stays in place.

`scripts/compat/native-block-boot.py` cold-boots a small native Linux guest with
one private raw disk. It verifies seed reads, an explicitly configured serial,
guest writes, a successful host backing-file flush with Writeback caching, and
actual OS poweroff. CI boots separate backing files with the same serial.
This verifies the device foundation; it does not expose managed volumes or
verify checkpoint consistency, crash recovery or disk migration. Those remain
required by #1329 and the stages above.

## Native confinement foundation (#1439)

The opt-in `confined_blocks` snapshot-load field declares ordered raw block
slots with caller-selected `disk-N` aliases, stable serials, fixed capacity and
read-only/root policy. Restores require a locally trusted prepared layout or
device-reference file and reject changed identity, paths, capacity, MMIO layout,
features or Writeback policy. Vhost-user blocks are unsupported. Empty bindings
retain the existing rejection. The selected backing must be a regular file of
the exact declared capacity. Snapshot data cannot set the transient file check.

`scripts/compat/native-block-restore.py` exercises the patched VMM directly.
It boots a small guest, saves a trusted reference and later checkpoint, retires
the original VMM, copies disk state into a distinct inode, and restores into a
fresh VMM. Checks cover inherited exclusive leases, missing-reference rejection
before opening the disk, actual backing-length rejection, stable serial and RAM
identity, host flushes, preserved disk contents and a new write that leaves the
retired source unchanged. Guest poweroff must complete with status zero.

This establishes the restore primitive. The oracle supplies its own trusted
layout, files and leases. Managed VM attachments, durable ownership fencing,
coherent disk generations, automatic migration transfer and software-backend disk
integration remain required under #1329 before exposing managed attachments.
