# Software VM lifecycle implementation contract

This is the implementation plan for #1358 and the lifecycle portion of #1327.
The `flexvm software --name` command owns a QEMU TCG VM through the normal
registry and management socket. Local `stop` and `start` now capture and restore
its RAM, devices, guest processes and foreground session through a fresh engine.
The snapshot includes verified engine, kernel, root filesystem and x86 firmware
copies, and a durable local ownership journal prevents implicit replay after a
restore has been granted CPU authority. A failed restore after that grant remains
quarantined; it is never silently restarted from the older state.

Stopped software VMs can transfer across hosts with signed ownership handoffs.
Software snapshots currently use private user networking, and open host network
connections close on a move. Persistent disk transfer, routed network continuity,
elastic memory, hierarchy ownership and explicit quarantine recovery remain work
to implement. Unknown or older guest agents cannot checkpoint; a
current serial agent must acknowledge its request and transport barriers.

`scripts/compat/software-lifecycle.py` exercises two normal CLI stop/start cycles
with both host virtualization devices masked. It checks PID/start-time, a random
volatile RAM canary, advancing counters, a single workload boot, contiguous
foreground output, retired engine cleanup and rejection of a corrupted kernel. It also injects a
parent-directory fsync error after checkpoint replacement, explicitly rolls back
the paused source and checks that a new capture succeeds without losing its
verified inputs, including a foreground garbage-collection pass while the live
engine retains the exchanged input bundle.

Software staging and atomic journal writers use versioned temporary names and
directory leases. Collection skips active captures and all prepared or consumed
input bundles. After an exchange, an abandoned hidden input bundle is reclaimed
only once its recorded engine identity is proven gone. Public checkpoint manifests,
execution grants, retirement records and quarantined snapshots are preserved;
only recognized journal temporaries are removed there. Earlier unleased temporary
names are retained for compatibility with concurrent older writers.

Versioned private software runtime roots record the owning process and each QEMU
or vsock backend by full process identity. Children inherit the runtime directory
lease and, for named VMs, the charged RAM hold. An abrupt owner death therefore
keeps RAM charged until its children exit. Recovery signals recorded children via
pidfds, waits for exit, then requires an exclusive runtime lease before removing
paths. An unrecorded child in the spawn-to-record crash window keeps both leases
until PDEATHSIG terminates it. Unknown records and namespace-invisible processes
are preserved; canonical quarantine and ownership journals are never replayed by
runtime cleanup.

With `--firecracker`, the lifecycle fixture runs an unchanged Firecracker inner
Linux guest through the same OCI/agent and named-owner path. Its inner PID 1
alternates between a sustained CPU loop and timer sleeps. Observations retain the
outer supervisor and VMM PID/start time, inner process identity, separate RAM
canaries, an inner counter and monotonic time. The test repeats normal
pause/unpause, fresh-owner stop/start, rollback and publication-owner-death
recovery, and checks that the inner guest boots once. It also transfers a
checkpoint with the inner CPU loop active, checks that both levels retain
their process and memory identity, and requires fresh inner timer and CPU
progress before an orderly shutdown.

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
mode nested page walks. The pinned x86 engine is 10.2.1 with the TCG SVM restore fix from
`scripts/build-qemu.sh` (package `flexvm-tcg-nested-1`). Stock Linux builds can
incorrectly require KVM's opaque nested-state blob when restoring TCG while a
vCPU is in SVM guest mode. The patch restricts that validation to the KVM
accelerator; TCG's architectural SVM/NPT state uses its existing serialization.
ARM uses Cortex-A72 with EL2;
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
permission for another target or snapshot. The destination requires that receipt
and commits its journal before resuming.
Recovery never automatically resumes an ambiguously transferred source; it
remains fenced until the journal protocol resolves ownership. Retry receipts
idempotently, and retain the source tombstone across owner/host restarts. Test
every crash window, including retirement recorded before the source exits, and
destination commit before its acknowledgment reaches the source.

The transfer journals use `flexvm software-transfer`. Run `id` on the
destination to get its host ID, then `offer VM DESTINATION` on the source
after the software VM has stopped. The offer identifies the exact unconsumed
checkpoint and the next generation. On the destination, use
`prepare OFFER --source-key KEY` with the source's trusted 32-byte Ed25519
public key in standard padded base64.

On the source, `retire VM OFFER --signing-key FILE --destination-key KEY`
pins the destination's separately configured Ed25519 public key. It checks
that the exact checkpoint is retired and that neither its owner nor engine is still alive.
It writes a durable restart fence keyed by VM identity before returning the
signed receipt. The private key must be a private, locally owned regular file
containing Ed25519 PKCS#8 DER. Keep the source checkpoint for receipt retries
and artifact transfer. Retirement blocks local starts, including grants that
were prepared before the fence was written. If the destination aborts, run `acknowledge-abort OFFER --signing-key FILE`
there. It durably rejects the offer before signing the acknowledgment with the
destination key. Its message uses the same offer encoding with the separate
domain `flexvm/software-abort/v1` followed by a NUL. Run
`recover ABORT-RECEIPT` at the source. A valid acknowledgment for the exact
fence permits restart above that transfer generation. A recovered source
retains the generation floor, and a previous acknowledgment cannot release a
newer fence. Use portable matching artifacts on both hosts.

An offer is a JSON object with these fields in wire order:

1. `vm_id`
2. `source_host`
3. `destination_host`
4. `transfer_id`
5. `manifest_sha256`
6. `generation`

The first four fields are 32 lowercase hexadecimal characters. The digest is
64 lowercase hexadecimal characters and the generation is a positive integer.
`commit RECEIPT` verifies a JSON object containing the original `offer` and a
standard padded base64 `signature`. The Ed25519 message is the ASCII bytes
`flexvm/software-retirement/v1`, one NUL, and the compact JSON offer serialized
in the field order above. The destination pins the public key and offer at
preparation. A commit retry verifies the same receipt. `abort OFFER` permanently
rejects that offer, and a replacement needs a higher generation and a different
transfer ID. These commands record ownership decisions for subsequent activation.

For a prepared destination and a retired source, run
`software-transfer send VM OFFER` on the source. Pipe its stdout into
`software-transfer receive OFFER` on the destination, for example through SSH.
Both sides use the same offer file. The receiver enforces a 16 GiB artifact
limit by default, configurable with `--max-bundle-mib`, and reserves disk
space before writing each member. It publishes the bundle under
`STATE/software-incoming/VM-ID-TRANSFER-ID` after digest verification and
a final check that the exact offer is still pending or committed. Retrying
the same transfer rechecks the stored bytes.

The stream starts with `flexvm-software-bundle-v1` and a newline, followed by
the four-byte big-endian header length and a JSON object with `offer` and
`manifest`. Raw members follow in the order engine, kernel, root filesystem,
VM state, and firmware in manifest key order. The manifest supplies every
length and digest. A truncated, extended or corrupted stream fails verification.
The published bundle carries artifacts and the offer identity. After the
destination commits the retirement receipt, run
`software-transfer activate OFFER VM --qemu FILE` there. Choose a locally
trusted QEMU binary with exactly the engine digest and size in the bundle.
FlexVM launches from the local descriptor, loads the guest with its CPUs
paused, and records its one-time execution grant in the host journal before
resuming. A retry before the grant uses the same destination name and a newer
generation. The grant survives removal of the VM or its imported artifacts.
After activation, ordinary destination `stop` and `start` use local checkpoints.

The destination can reclaim an import after a clean shutdown or after
retirement publishes its replacement local checkpoint. `flexvm debug gc`
collects those imports and obsolete destination bundles once their
readers and engines have exited. The durable activation decision remains.
If the owner failed without a clean retirement, the import is retained
for recovery.

To return to the previous host, repeat the same commands with source and
destination reversed. The returning offer must advance the generation and
use the host identity and signing key pinned by the last outbound handoff.
Activate under a free name if the previous local checkpoint still holds its
old name. That checkpoint stays fenced after the return. Only a checkpoint
captured by the new local owner can start or transfer again.

To obtain a finalized handoff proof, run
`software-transfer acknowledge-commit OFFER --signing-key FILE` with the
destination signing key. Pass its signed output to
`software-transfer finalize COMMIT-ACK --signing-key FILE` with the source
signing key. The source verifies the commit against the pinned destination key
and records the decision before issuing the proof. The same transfer cannot
both finalize and recover from an abort. The proof binds the preceding
inbound offer if the VM arrived through a transfer and activated here.

For a return through intermediary hosts, pass
`--handoff-chain FILE` to `prepare`. The file is a JSON array containing
the finalized proofs in transfer order, beginning with the first move
after the destination's last outbound fence. For A→B→C→A, supply the
finalized B→C proof when preparing C→A on A. Each link must name the
preceding offer and advance the VM's generation. The final link identifies
the returning source and key supplied to `prepare`.

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

## Software guest addresses

New software guests use private IPv4 `10.0.2.15/32`, gateway `10.0.2.2` and
DNS `10.0.2.3` on the isolated QEMU user network. The bootstrap receives its
IPv4 gateway through an explicit kernel argument. Native VM networking keeps
its existing gateway.

Saved guests from the original software profile retain address `169.254.1.2`,
gateway `169.254.1.1` and DNS `169.254.1.3`. Restore accepts only complete
canonical profiles generated locally for these two layouts. It rebuilds the
engine command from the matched layout and fresh host endpoints, preserving
the selected layout on subsequent captures. Manifest arguments are never
executed directly. Active and saved guest metadata report the selected address.
