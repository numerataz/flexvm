# Software VM lifecycle implementation contract

This is the implementation plan for #1358 and the lifecycle portion of #1327.
The `flexvm software --name` command owns a QEMU TCG VM through the normal
registry and management socket. Local `stop` and `start` now capture and restore
its RAM, devices, guest processes and foreground session through a fresh engine.
The snapshot includes verified engine, kernel, root filesystem and x86 firmware
copies, and a durable local ownership journal prevents implicit replay after a
restore has been granted CPU authority. A failed restore after that grant remains
quarantined; it is never silently restarted from the older state.

This is a local lifecycle milestone, not completion of this contract. Software
snapshots currently use private user networking: open host network connections
are not preserved. Cross-host migration, persistent disk transfer, routed network
continuity, elastic memory, hierarchy ownership and explicit quarantine recovery
remain work to implement. Unknown or older guest agents cannot checkpoint; a
current serial agent must acknowledge its request and transport barriers.

`scripts/compat/software-lifecycle.py` exercises two normal CLI stop/start cycles
with both host virtualization devices masked. It checks PID/start-time, a random
volatile RAM canary, advancing counters, a single workload boot, contiguous
foreground output, retired engine cleanup and rejection of a corrupted kernel.

## Execution and state identity

Persist an explicit backend discriminator alongside every machine and snapshot.
Firecracker records retain their current loader; software snapshots use a new,
versioned format and never enter the Firecracker pager or snapshot loader.
A software snapshot must record:

- Architecture, exact engine binary digest and QMP version, board and CPU profile,
  vCPU count, RAM layout/size, firmware/DTB digests and the ordered device
  configuration, including CPU feature flags, EL2 and GIC options.
- Kernel and immutable root filesystem content digests, guest control protocol
  version, boot arguments, and root filesystem format.
- VM identity, snapshot identity, transfer identity, owner generation and guest
  attachment epoch and saved request-barrier generation/sequence; guest address,
  network identity and persistent disk identities.
- Digest and length of every state, memory and disk artifact, plus the manifest
  format version. Paths supplied by a manifest cannot select arbitrary host files.

The minimum engine version applies to new boots. Initially require an exact
engine/profile match for restore. Validate the entire
manifest and referenced artifacts before starting the destination engine. Reject
unknown formats, missing artifacts, changed content and incompatible profiles with
specific errors. Open artifacts without following symlinks, verify their open
descriptors, and pass those same descriptors to the engine. Verification followed
by reopening a pathname is insufficient. Staging and published artifacts must be
owned by the host and inaccessible for writes by guests or other principals. No implicit conversion between engines or architectures.

The x86 profile keeps SVM and NPT enabled and requires QEMU 9.2 or newer for real
mode nested page walks. The tested engine is 10.2.1. ARM uses Cortex-A72 with EL2;
the max/VHE cold-restore failure remains a documented profile limitation.

## Ownership and guest requests

A VM owner serializes start, pause, resume, checkpoint, transfer and destruction
under one operation lock. Track engine process identity through owned child
handles; a PID alone is insufficient. Owner exit terminates and reaps owned
engines and closes the private control endpoints. Recover abandoned records
without treating an unrelated reused PID as the VM. Persist the host boot ID,
owner PID/start time, VM nonce and private endpoint identity. Verify these during
recovery; use pidfds while the live owner holds the processes.

Use virtio-serial for migratable software control. Disconnecting its host client
is necessary but does not by itself prove guest requests have drained. Introduce
an acknowledged guest quiescence barrier covering the serial dispatcher and
accepted requests. This requires a new `BARRIER 1` QUIESCE/ACK/RESUME agent protocol; reject agents
without it for checkpoint operations. The existing unversioned `QUIESCE` only
syncs filesystems and drops caches; its `ok` cannot acknowledge request quiescence. Its barrier covers
incomplete Yamux bodies and accepted asynchronous request setup. It does not wait
for user processes or long-lived output attachments to finish. Stop admission,
resolve or cancel outstanding operations,
acknowledge the barrier, then pause CPUs. Preserve guest processes and session
output across the checkpoint; a disconnected attachment does not terminate them.
Use persisted request identities for mutating operations, reusing session IDs for
command creation, and retain their acceptance/results across restore. An accepted
operation with side effects cannot be blindly retried as a fresh request. A
barrier timeout fails checkpointing rather than saving an ambiguous request.
After ACK, the dispatcher refuses new work until an idempotent RESUME for the
same barrier identity. Bound the deduplication table; reject expired identities
as expired rather than executing them anew. Protocol deadlines and retention
use monotonic time or host-issued counters, never guest realtime. Retire entries
only after explicit
result acknowledgment and after their generation can no longer attach.

On restore establish a fresh control connection and the guest's existing
`FENCE generation epoch` protocol before attaching sessions. Keep monotonic
claim numbers and stream offsets. Old owners and delayed old requests must fail
without changing guest state or duplicating command execution. Management and
Docker API calls must use the same owner and lifecycle state machine: route
requests through its admission gate and return the existing retryable checkpoint
or paused response while admission is closed.

## Checkpoint and restore

1. Acquire the operation lock, close admission and acknowledge guest quiescence.
2. Pause through QMP and verify the actual engine state. Account for device and
   network operations that were already in flight.
3. Drain pending block I/O through the engine block layer, flush the backing
   stores, and capture writable disk snapshots at the same paused device boundary.
   Failure to establish that boundary fails the checkpoint. Export QEMU state and
   RAM through an owned descriptor with `getfd`/`migrate`.
   Bound every command and transfer by a deadline; require migration completion.
   Include immutable root references and writable disk contents in the snapshot.
4. Write artifacts into a private staging directory, synchronize their contents,
   and atomically publish the manifest only after all digests are final. An
   incomplete checkpoint must never replace the last committed one.
5. For suspend, retire and reap the source engine before publishing it as stopped.
   For a retained source, explicitly leave migration state through a supported
   engine transition and verify pause or resume; failure leaves the VM fenced
   and visibly failed. Source resume is forbidden after destination write or CPU
   ownership has been granted.
6. Restore in a fresh process, load all state while paused and verify completion.
   Establish the host transport endpoint, then durably commit destination CPU and
   disk ownership before running any guest instructions. Resume CPUs with network
   traffic held, public command admission closed and the saved guest barrier still
   closed. Guest CPUs must run to acknowledge FENCE, clock updates and RESUME;
   those requests cannot be completed while the engine is paused. Only after
   maintenance acknowledgments succeed, activate routing, release held traffic
   and publish the VM as running. On failure pause the target and retain its
   committed ownership; never revive the retired source. Rollback cannot leave
   both copies running.

Use durable transfer journals on both hosts, without requiring shared storage.
Only after the checkpoint is committed, the source records its irrevocable
retired generation, stops and reaps its engine, then issues a retirement receipt.
Retain the committed source snapshot until the destination durably commits and
retains a verified recovery copy. Before retirement, a failed transfer may resume
the source; disks remain frozen between capture and resolution. After retirement,
that generation can never resume. Recover from retained artifacts under a fresh
generation only after the destination acknowledges a durable abort/retirement
record that permanently rejects the old transfer receipt. No acknowledgment means
the source remains fenced, even after a timeout. There is no timeout-based
operator override in the initial implementation. Each owner durably records the
highest generation seen; recovery chooses a generation above those acknowledged
by both hosts, and every resume checks that record and any aborted transfer IDs.
An unresolved destination outcome never permits unilateral resume.

Authenticate receipts using explicitly configured trusted host signing keys;
unsigned or unknown-host receipts cannot authorize restore. Bind the VM, source
and destination identities, transfer ID, retired generation and complete manifest
digest, including every disk digest. The target checks all bindings against its
prepared state and durable generation record; a receipt is not a reusable bearer
permission for another target or snapshot. Cross-host migration stays unavailable
until this trust and replay protection are implemented and verified.
The destination requires that receipt and commits its journal before resuming.
Recovery never automatically resumes an ambiguously transferred source; it
remains fenced until the journal protocol resolves ownership. Retry receipts
idempotently, and retain the source tombstone across owner/host restarts. Test
every crash window, including retirement recorded before the source exits, and
destination commit before its acknowledgment reaches the source.

After load, use the guest agent to step CLOCK_REALTIME from the current host time.
Do not reset CLOCK_MONOTONIC through the agent. Preserve the engine virtual clock
and device timers through migration, and test nondecreasing monotonic time and
nested timer progress across pause/restore. Guest workloads may execute during
the quarantined maintenance interval, before the realtime correction; do not
promise that their first restored clock read already matches host time. A clock
or fencing setup failure pauses the destination and keeps admission closed. Realtime corrections use clock_settime, including
backward steps when host time is behind; preserve the kernel's normal clock-change
notifications. Test cancel-on-set realtime timers and monotonic time separately.

Begin with eager, complete RAM state. Reserve and account for its full committed
memory. Elastic memory and demand paging require their own engine integration;
fixed RAM must not be reported as elastic or charged only for initial RSS. Guest
KVM child memory already lives in its parent RAM reservation and is charged
there. A parent-managed sibling engine needs its own reservation against the
same hierarchy budget; do not double-charge guest-resident child RAM. Reserve
the full destination RAM before loading state. Failed admission returns a
resource error without a partial load; every later failure releases reservations.

## Storage and networking

Transfer writable disk state automatically with the VM, as requested in #1329.
Snapshot each disk at the same consistency boundary as CPU and RAM. Capture a
full copy or immutable copy-on-write version; retaining a reference to a writable
live disk is insufficient. On a failed transfer before retirement, unfreeze the
source only after leaving migration state; subsequent writes cannot alter the
committed snapshot. Verify disk
identity, content and size before attaching the destination. Retire the source's
write ownership before granting the destination write access. Test interrupted
transfers, retries and recovery after either owner crashes. Shared storage cannot
become an undocumented prerequisite.

Persistent lifecycle networking must retain the VM's routed address and MAC.
The VM owner creates the TAP through the existing network machinery and passes
its owned descriptor to QEMU using a TAP netdev with an explicit inheritance
whitelist. Keep TAP, route and held-packet ownership in the common owner rather
than in an engine-specific record. Include held-packet buffers and delivery
positions in the transfer. Guest virtio queues are saved with RAM/device state.
Held-buffer delivery follows ordinary network retry semantics: preserve TCP
stream continuity, while UDP duplicates/loss remain observable network behavior.
The source withdraws its active route and holds
traffic before export; the destination publishes its route after ownership
commit. Verify destination route updates, source withdrawal and packet delivery
under the existing migration ordering before enabling the backend. The foreground userspace
network stack has no established cross-host connection continuity contract.
Require TCP and UDP continuity tests before advertising migration for that mode;
changing the guest address or silently dropping connections is insufficient.

## Acceptance gates

- No-host-KVM boot, argv/credentials/cwd/env, real containers and guest KVM clients
  run through the actual OCI/agent path on native x86 and ARM in GitHub Actions.
- Cold restore preserves PID/start time, anonymous RAM contents, a running process
  counter, guest sessions and a freshly issued command. The source process exits;
  neither outer nor inner guest boots again.
- Nested clients survive pause, suspend/restore and migration while idle, while
  executing CPU code and with interrupts pending. A timer/input gate alone does
  not establish every nested execution state.
- Live network flows and disk writes survive transfer; interrupted transfers and
  owner crashes retain a single writer/owner and a usable last committed state.
- Persistent records support inspection, exec, stop/start, restart policies and
  Docker API operations with the same semantics as their advertised capabilities.
- Resource limits include nested guests. Destroying the parent destroys its owned
  hierarchy, and stale parent/child owners cannot regain authority after migration.
- Hierarchy transfer records enumerate all descendant identities and generations.
  Close child creation admission, freeze and retire all source descendants before
  issuing the parent receipt. Load all targets paused and commit one destination
  hierarchy journal before any target runs. The source retains the whole
  hierarchy tombstone across recovery; individual child restart cannot bypass it.
- Repeat the applicable lifecycle tests with optional hardware acceleration.
  Software-path success cannot substitute for nested hardware state verification.
  Use the authorized GCE environment for hardware tests where GitHub runners do
  not expose the required nested acceleration; record the exact host capabilities.
  Missing hardware coverage leaves the corresponding acceptance gate and issues
  open; it is not a skip that counts as successful verification.

Close #1358/#1327 only after their complete acceptance criteria pass. Narrow
milestones and engine experiments must leave those issues open.
