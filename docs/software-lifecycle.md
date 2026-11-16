# Software VM lifecycle implementation contract

This is the implementation plan for #1358 and the lifecycle portion of #1327.
The existing `flexvm software` command owns a foreground QEMU TCG VM. Persistent
records, restore, migration, elastic memory and hierarchy ownership remain work
to implement. Engine boot/checkpoint experiments establish prerequisites only.

## Execution and state identity

Persist an explicit backend discriminator alongside every machine and snapshot.
Firecracker records retain their current loader; software snapshots use a new,
versioned format and never enter the Firecracker pager or snapshot loader.
A software snapshot must record:

- Architecture, exact engine binary digest and QMP version, board and CPU profile,
  vCPU count, RAM layout/size, and the ordered device configuration.
- Kernel and immutable root filesystem content digests, guest control protocol
  version, boot arguments, and root filesystem format.
- VM identity, snapshot identity, transfer identity, owner generation and guest
  attachment epoch; guest address, network identity and persistent disk identities.
- Digest and length of every state, memory and disk artifact, plus the manifest
  format version. Paths supplied by a manifest cannot select arbitrary host files.

Initially require an exact engine/profile match for restore. Validate the entire
manifest and referenced artifacts before starting the destination engine. Reject
unknown formats, missing artifacts, changed content and incompatible profiles with
specific errors. No implicit conversion between engines or architectures.

The x86 profile keeps SVM and NPT enabled and requires QEMU 9.2 or newer for real
mode nested page walks. The tested engine is 10.2.1. ARM uses Cortex-A72 with EL2;
the max/VHE cold-restore failure remains a documented profile limitation.

## Ownership and guest requests

A VM owner serializes start, pause, resume, checkpoint, transfer and destruction
under one operation lock. Track engine process identity through owned child
handles; a PID alone is insufficient. Owner exit terminates and reaps owned
engines and closes the private control endpoints. Recover abandoned records
without treating an unrelated reused PID as the VM.

Use virtio-serial for migratable software control. Disconnecting its host client
is necessary but does not by itself prove guest requests have drained. Introduce
an acknowledged guest quiescence barrier covering the serial dispatcher and
accepted requests. Stop admission, resolve or cancel outstanding operations,
acknowledge the barrier, then pause CPUs. Preserve guest processes and session
output across the checkpoint; a disconnected attachment does not terminate them.

On restore establish a fresh control connection and the guest's existing
`FENCE generation epoch` protocol before attaching sessions. Keep monotonic
claim numbers and stream offsets. Old owners and delayed old requests must fail
without changing guest state or duplicating command execution. Management and
Docker API calls must use the same owner and lifecycle state machine.

## Checkpoint and restore

1. Acquire the operation lock, close admission and acknowledge guest quiescence.
2. Pause through QMP and verify the actual engine state. Account for device and
   network operations that were already in flight.
3. Export QEMU state and RAM through an owned descriptor with `getfd`/`migrate`.
   Bound every command and transfer by a deadline; require migration completion.
   Include immutable root references and writable disk contents in the snapshot.
4. Write artifacts into a private staging directory, synchronize their contents,
   and atomically publish the manifest only after all digests are final. An
   incomplete checkpoint must never replace the last committed one.
5. For suspend, retire and reap the source engine before publishing it as stopped.
   For a retained source, explicitly leave migration state through a supported
   engine transition and verify pause or resume; failure leaves the VM fenced
   and visibly failed.
6. Restore in a fresh process, load all state while paused and verify completion.
   Reconnect and fence control, reconcile network/clock state, then publish the
   destination ownership and resume. Rollback cannot leave both copies running.

Begin with eager, complete RAM state. Reserve and account for its full committed
memory. Elastic memory and demand paging require their own engine integration;
fixed RAM must not be reported as elastic or charged only for initial RSS.

## Storage and networking

Transfer writable disk state automatically with the VM, as requested in #1329.
Snapshot each disk at the same consistency boundary as CPU and RAM. Verify disk
identity, content and size before attaching the destination. Retire the source's
write ownership before granting the destination write access. Test interrupted
transfers, retries and recovery after either owner crashes. Shared storage cannot
become an undocumented prerequisite.

Persistent lifecycle networking must retain the VM's routed address and integrate
with the existing TAP/route/hold transfer machinery. The foreground userspace
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
- Repeat the applicable lifecycle tests with optional hardware acceleration.
  Software-path success cannot substitute for nested hardware state verification.

Close #1358/#1327 only after their complete acceptance criteria pass. Narrow
milestones and engine experiments must leave those issues open.
