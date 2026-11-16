# General Linux compatibility

The execution tracker is [#1332](https://github.com/numerataz/flexvm/issues/1332).
Each linked issue contains an implementation plan and acceptance criteria.
Support means a workload has passed its real execution and lifecycle tests;
an installed binary or successful capability inventory alone does not establish support.

| Workstream | Ticket | Execution order |
|---|---|---|
| Capability and lifecycle harness | [#1331](https://github.com/numerataz/flexvm/issues/1331) | First: isolated probes, ownership/cleanup, lifecycle state |
| Guest kernel capabilities | [#1330](https://github.com/numerataz/flexvm/issues/1330) | Audit, reproducible kernel/configuration, runtime verification |
| Guest kernel modules and matching SDK | [#1380](https://github.com/numerataz/flexvm/issues/1380) | Native guest compilation/DKMS, ABI checks and loaded module lifecycle |
| Usable RAM-filesystem capacity | [#1333](https://github.com/numerataz/flexvm/issues/1333) | Unblock ordinary package installation |
| Podman and rootless Docker | [#1322](https://github.com/numerataz/flexvm/issues/1322) | User namespaces/helpers, storage, network, delegation |
| containerd, nerdctl and BuildKit | [#1323](https://github.com/numerataz/flexvm/issues/1323) | Direct runtimes, CNI, snapshotters and image builds |
| Namespace sandboxes and gVisor | [#1326](https://github.com/numerataz/flexvm/issues/1326) | Bubblewrap/unshare first, then complete sandbox runtimes |
| k3s and kind | [#1324](https://github.com/numerataz/flexvm/issues/1324) | Node, pods, DNS/services, networking, storage |
| Distro init as guest PID 1 | [#1328](https://github.com/numerataz/flexvm/issues/1328) | Agent/service contract, systemd/OpenRC, user sessions |
| systemd-nspawn and LXC/Incus | [#1325](https://github.com/numerataz/flexvm/issues/1325) | System containers, services and unprivileged instances |
| Durable writable disks | [#1329](https://github.com/numerataz/flexvm/issues/1329) | Storage identities, fencing, checkpoint and migration consistency |
| Inner QEMU/KVM and FlexVM | [#1327](https://github.com/numerataz/flexvm/issues/1327) | CPU exposure, guest KVM, nested state/lifecycle correctness |

Docker's existing verified case remains `scripts/test-docker.sh`; its setup is in
[Docker inside a VM](images.md#docker-inside-a-vm).

## Capability and lifecycle runner

On a KVM host, with `flexvm` installed, a C compiler/static libc available, and
registry access:

```sh
sudo scripts/compat.py --phases run,suspend,checkpoint --output /tmp/compat-result
```

The runner compiles a static probe for the host/guest architecture, pulls an
isolated Ubuntu image/template, creates a uniquely named VM, and writes
`report.json`. Its namespace case verifies a mounted filesystem marker and a
live process's identity through each phase. Its own VM, checkpoints and template
are removed on success, failure, or interruption. Registry layers stay cached.
Commands are bounded; failures preserve the report and available guest logs.

`--bin`, `--state` (or `FLEXVM_STATE_DIR`) and `--run` select the source host.
`--probe-binary` supplies an already-built static probe, avoiding a compiler
requirement on the execution host. The binary must match that host's architecture.

To inspect an existing VM without running lifecycle operations:

```sh
sudo scripts/compat.py --vm my-vm --case capabilities --output /tmp/my-vm-capabilities
sudo scripts/compat.py --vm my-vm --require storage.fuse --output /tmp/my-vm-fuse
```

This copies/removes its own temporary probe file and runs bounded child probes;
it does not rebuild, stop or destroy the existing VM. Tests use private namespaces
and remove their temporary cgroup/filesystem resources.

An inventory records each probe's `supported`, `denied`, `missing`, `unconfigured`,
`unsupported` or `error` status and errno. A missing device is reported as missing, not assumed
to prove that a kernel feature is disabled. The overall inventory can succeed
with unavailable optional features. `--require PROBE` makes such a result fail;
required baseline namespace capabilities also fail instead of becoming skips.

Probes cover user/mount/PID/network/IPC/UTS/cgroup namespaces, writable cgroup v2
memory/CPU/PID limits, overlay mounts, filesystem capacity, FUSE mounts, TUN/TAP
creation, enforced seccomp filtering, BPF map creation, perf events, pidfds,
memfds, io_uring, nftables/conntrack queries, legacy iptables and KVM VM creation.
They test individual facilities, not every operation a runtime might need.

## Migration

A configured local peer must use compatible CPU/kernel/Firecracker artifacts
and identical templates, following the normal [migration setup](../README.md#migrate).
The runner does not change host configuration or start listeners for the caller.
Give the peer's local state/run directories so it can exec and clean up after
migration:

```sh
sudo scripts/compat.py --phases run,suspend,checkpoint,migration \
  --migration-to 127.0.0.1:7151 --to-state /var/lib/flexvm-peer \
  --output /tmp/compat-migration
```

Migration is the last phase. A stopped checkpoint is used so that the baseline
does not require userfaultfd write protection. Workload-specific tests must
add assertions for their own container/process state, traffic and data; passing
the baseline is not a substitute for those tests.

## Container workload cases

`--workload PATH` runs a guest shell script in an isolated VM. The runner sends
it `prepare NONCE run` once, then `verify NONCE PHASE` after each requested
lifecycle transition. Preparation can install packages and start persistent
workloads; verification must assert their live state. A script failure fails the
suite and still removes the owned VM/checkpoints/template. The report records
the script name, SHA256 and output. Scripts run as guest root and are rejected
with `--vm`, which protects existing guests from workload setup changes.

The Podman case uses stock Ubuntu packages, FUSE overlay storage, subordinate
UID/GID mappings, and an explicitly delegated cgroup-v2 subtree for a rootless
session. It tests rootful and rootless image pulls, builds, real CPU/memory/PID
limits, outbound DNS/HTTP, custom bridge DNS, bind mounts, named volumes, a live container process, and published
ports through each phase:

```sh
sudo scripts/compat.py --memory-mib 2048 \
  --workload scripts/compat/workloads/podman.sh \
  --phases run,suspend,checkpoint --output /tmp/compat-podman
```

Use the migration options above to include migration. The standalone runner
uses the configured hosts' guest DNS and outbound routing/NAT.

The `podman` case in `scripts/e2e.py` automates all four phases with a pinned
upstream Ubuntu image and a pinned multi-architecture BusyBox image. Its test
coordinator installs temporary NAT/forwarding rules scoped to its own guest
address ranges and supplies reachable host DNS; it removes those rules on
completion or interruption, including after worker failure. `FLEXVM_TEST_DNS`
can override resolver discovery. This setup belongs to the test harness;
FlexVM's normal routed-networking policy is unchanged. Reports under the
selected log directory record package versions, image identities, capability
results, workload output and cleanup errors.

```sh
sudo scripts/e2e.py --jobs 1 --no-image --faults '' podman
```

This case requires a KVM host and the expanded guest kernel with FUSE, TUN and
container networking enabled. Rootless Docker and service-managed user sessions
remain separate acceptance work in #1322/#1328.

## Namespace sandbox acceptance

The `namespace_sandboxes` E2E case installs ordinary Ubuntu packages for chroot,
util-linux `unshare`, and bubblewrap. It verifies an isolated root filesystem,
unprivileged user/PID/mount/network/UTS/IPC namespaces, read-only mounts, and an
explicit seccomp filter. A live bubblewrap process must retain its random cookie,
PID/start time and fresh in-memory counter progress through all lifecycle phases.

The same case installs the complete SHA256-pinned upstream gVisor
`release-20261109.0` archive for its architecture, including companion binaries.
It selects `systrap`, with guest `/dev/kvm` and `/dev/vhost-vsock` masked. Real OCI
containers exercise filesystem/process isolation, bridge DNS, outbound HTTP and
published ports; their process identity, random cookie and fresh counter progress
must survive suspend/start, checkpoint/restore and migration. This is gVisor's
software isolation backend; outer FlexVM execution in this E2E case uses KVM.
The runtime installation layout follows the [upstream guide](https://gvisor.dev/docs/user_guide/install/).

```sh
sudo scripts/e2e.py --jobs 1 --no-image --faults '' namespace_sandboxes
```

The coordinator supplies temporary test egress as for Podman. CI retains the
machine-readable compatibility reports on success and failure. For configured
hosts, `scripts/compat.py --workload scripts/compat/workloads/namespace-sandboxes.sh`
also runs the workload with its ordinary source/peer lifecycle options.

## Initial audit

The pinned 6.1.155 guest kernel passed the basic namespace, cgroup, overlay,
seccomp, BPF-map, perf, pidfd, memfd, io_uring and legacy iptables probes on an
x86_64 cloud KVM host. FUSE, TUN/TAP and KVM devices were missing; nftables and
conntrack netlink returned `EPROTONOSUPPORT`. Those findings are tracked as
work, not advertised as supported. Root filesystem capacity reporting and
non-root setuid-helper policy also need fixes for ordinary package managers
and rootless runtimes. Future reports must name the tested build and workload
before promoting a workstream's support status.

## Verified development results

On an x86_64 GCE n2-standard-8 host with nested virtualization enabled, the
expanded 6.1.155-flexvm kernel and guest privilege/device fixes passed all 23
capability probes. Docker 27's existing smoke case also passed with native
overlay2, bridge networking, limits, builds, volumes and suspend/resume.

The Podman case passed `run,suspend,checkpoint,migration` with Ubuntu 24.04
packages: Podman 4.9.3, crun 1.14.1, fuse-overlayfs 1.13, slirp4netns 1.2.1,
netavark 1.4.0 and aardvark-dns 1.4.0. Both rootful and rootless containers
preserved their process identity, mounted volume contents and published ports.
The script specifies complete storage paths, the netavark backend, required
iptables packages, delegated rootless controllers, and a separate leaf cgroup
for Buildah's build process. None of the checks disable cgroup enforcement or
silently switch storage/networking to a reduced mode.

QEMU 8.2.2 with forced KVM acceleration booted an inner Linux guest and advanced
its serial counter. Outer suspend/resume failed the subsequent guest exec check;
nested KVM lifecycle support remains open in #1327. Rootless Docker, standalone
containerd/builders, Kubernetes, system containers, distro init and durable disks
still require their own acceptance results. These development results do not
establish support for every architecture or workload.

## KVM ABI and software execution checks

The architecture requirement is tracked in #1358 and #1327: host KVM is optional,
and existing programs using the KVM interface must work unchanged. The current
Firecracker backend still requires working KVM; the following checks establish
reference behavior and an execution-engine baseline for the replacement work.

`scripts/compat/kvm-abi.c` executes an x86 guest directly through the KVM ABI.
It checks real IO exits and the shared run page, coherent caller-owned RAM,
isolated VM descriptors, register save/restore, memory slot replacement/removal,
ioeventfd delivery/deassignment, and vCPU lifetime after its VM descriptor is
closed. The same static binary accepts a device path so it can later test the
FlexVM-compatible provider unchanged. Missing required capabilities or an
unusable device fail the test. GitHub Actions runs it against real KVM in the
first x86 integration shard.

`scripts/compat/software-boot.py` boots a real native Linux kernel with QEMU TCG,
a tiny static guest init, timer checks and clean poweroff. It masks `/dev/kvm`
inside a private mount namespace and traces file operations to reject attempts
to access that device. Independent x86_64/aarch64 GitHub Actions jobs retain the
machine-readable report, guest console and syscall trace.

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror -static -pthread scripts/compat/kvm-abi.c -o /tmp/kvm-abi
/tmp/kvm-abi /dev/kvm
sudo python3 scripts/compat/software-boot.py \
  --kernel /var/lib/flexvm/artifacts/vmlinux --output /tmp/software-boot
```

The software boot check is not a FlexVM software backend or a KVM API
implementation. Those remain required work; a successful TCG boot alone does
not satisfy unchanged-client compatibility or the FlexVM lifecycle contract.

On ARM64, `software-boot.py --guest-kvm` also enables emulated EL2 and GICv3,
then runs a static program using the normal guest Linux KVM API. It creates a
VM/vCPU, maps caller-owned RAM, sets ARM core registers, executes instructions,
checks an MMIO write exit, and requires a PSCI shutdown event. Host KVM stays
masked and the host trace must still show no KVM access. This experiment tests
the ordinary guest KVM implementation under CPU emulation.

Adding `--guest-firecracker PATH` runs that unchanged ARM Firecracker executable
inside the software-backed guest. It boots a second Linux kernel with its own
static init, requires independent timer progress, and checks clean inner guest
poweroff and hypervisor exit. ARM GitHub Actions uses the pinned published
Firecracker artifact, with its normal seccomp filter enabled; the report records
the executable's SHA256. Host KVM remains inaccessible throughout. This establishes
an unchanged hypervisor execution case, not nested lifecycle support, performance
guarantees, or an integrated FlexVM software backend.

`--checkpoint` adds a cold restore while the inner Linux guest is running.
The inner guest waits for console input after tick 0, so the host can stop the
outer emulator without racing a timer. The runner saves its complete machine
state, exits the source emulator, restores into a fresh process, then sends
the release token through the restored console devices.
Ticks 1 and 2 must come from the restored VM, with no repeated outer/inner boot
marker, followed by clean inner and outer shutdown. Both emulator processes
keep host KVM masked and traced. The report includes the migration result and
snapshot size; temporary machine RAM is removed after the test. ARM CI runs
this case with the Cortex-A72 CPU profile, which supports ordinary Linux KVM.

The `max` CPU profile passed nested boot but stalled on cold restore with
QEMU 10.2.1; a plain outer guest also stalled when restored during a timer
sleep. Cortex-A72 continued the live inner guest across the same sequence.
These results establish a tested software CPU profile, not support for every
emulated CPU feature, migration between engines/CPU profiles, or FlexVM's
existing snapshot format.

## Experimental software backend

`flexvm software` cold-boots an OCI image with QEMU TCG, the real FlexVM guest
agent, and a userspace virtio-vsock device. It requires neither host `/dev/kvm`
nor `/dev/vhost-vsock`. The foreground command owns both engine processes and
removes them when the guest command exits, startup fails, or it is interrupted.
Image preparation currently requires root, as with the existing image builder.

Install QEMU with its seccomp and userspace networking support. The x86 software
profile requires QEMU **9.2 or newer**: older engines omit nested page walks in
real mode ([upstream fix b56617bbcb47](https://github.com/qemu/qemu/commit/b56617bbcb47)).
Ubuntu 24.04's QEMU 8.2 reproduced a stall on the first nested vCPU run; disabling
NPT passed the ABI probe but loses nested paging performance. FlexVM retains NPT
and rejects old x86 engines before running the workload. CI builds the pinned
10.2.1 source with `scripts/build-qemu.sh INSTALL_PREFIX`, then tests unchanged
clients with both host virtualization devices masked. ARM retains its separately
tested distribution engine and Cortex-A72 profile.

Install the reviewed userspace vsock tool:

```sh
cargo install vhost-device-vsock --version 0.3.0 --locked
sudo flexvm software --kernel /var/lib/flexvm/artifacts/vmlinux \
  --vsock-backend "$HOME/.cargo/bin/vhost-device-vsock" \
  public.ecr.aws/docker/library/busybox:1.36 /bin/echo hello
```

The kernel needs virtio PCI on x86_64; ARM uses virtio MMIO and the PL011 console.
These transports are included in the v0.5.1 kernel recipe, along with PCI MSI
interrupt support. `--kernel` is explicit because a Firecracker template's saved machine state cannot be loaded by QEMU.
`--qemu PATH` selects the executable; `--mem MIB` (default 512) and `--vcpus N`
(default 1) select fixed guest resources. `--timeout SECS` bounds boot, not the
lifetime of the guest command. Image `--env`, `--workdir`, `--user`, `--entrypoint`
and `--cmd` options apply, and the command returns its guest exit status.
Networking uses QEMU's userspace stack with no TAP device, and fresh vsock
backends have private Unix sockets and independent CID spaces.

Unnamed software execution is a foreground command. Add `--name NAME` for
normal VM records and local lifecycle operations, described below. Restart
policies, elastic memory, Docker API lifecycle and migration still need integration. QEMU's vhost-user-vsock frontend currently blocks migration;
its device state/reset contract must be implemented and tested before it can
replace the existing Firecracker lifecycle path. ARM exposes emulated EL2, and
x86 TCG exposes AMD SVM, for the ordinary guest Linux KVM drivers. Intel VMX is
not the x86 software profile. The previous statement that TCG lacked both VMX
and SVM was incorrect. Hierarchical lifecycle integration and optional
parent-level child scheduling remain tracked in #1358/#1327.

The native x86/ARM CI acceptance case masks both host virtualization devices,
traces the complete process tree, pulls BusyBox, boots the real agent, and checks
literal argv, environment, workdir, non-root UID/GID, writable overlay state,
stdout/stderr and exit status 7. A second workload verifies that signaling only
the owner ends both engines and removes their private sockets. Reports record the executable/kernel/backend
identities and retain the console and syscall trace.

Add `--docker` to `scripts/compat/software-agent.py` to boot a stock Docker-in-Docker
image through the same software backend. Native x86/ARM CI includes this case. It
starts a real Docker daemon with the `vfs` storage driver and cgroup v2, imports
a small BusyBox image from the guest runtime, and checks memory/CPU/PID controller
settings, outbound HTTP, a bind mount and a
named volume read by a second container. It also requires BuildKit to execute an
uncached Dockerfile `RUN`, export an image and run that image with its expected
output, using the imported base image without another registry pull. This covers
Docker's bundled BuildKit; standalone/rootless BuildKit and containerd/CRI remain
separate acceptance cases. The complete host process tree remains
device-masked and traced. This establishes basic container operation under TCG;
it does not establish rootless Docker, overlay storage, persistent VM lifecycle
or a performance guarantee. Docker console output and its syscall trace are
retained beside the agent report.

`--control serial` selects an additional guest-management path over QEMU's
virtio-serial device. It does not start a userspace vsock backend, and rejects
`--vsock-backend`. The agent keeps the dedicated guest device root-only. A
Yamux connection provides bounded, flow-controlled concurrent streams; local
socket bridges retain request deadlines, half-close behavior and full-close
cancellation. Each stream is acknowledged after admission to the ordered guest
dispatcher, before its socket is exposed to the caller. Native x86/ARM CI runs
the full agent/Docker/BuildKit acceptance case through both control paths and
checks that user 1001 cannot read or write the serial management device.

This removes the vhost-user-vsock device from that execution profile. It is a
prerequisite for the local software checkpoint path described below. Vsock remains
the default for unnamed commands; named software owners use serial control.

`scripts/compat/software-kvm.py` runs real KVM clients inside an ordinary OCI
image using the software CLI and serial agent transport. On x86 it runs all nine
KVM ABI reference checks, including coherent/concurrent caller RAM, ioeventfd,
descriptor lifetime and vCPU state. ARM runs its architecture-specific KVM probe.
The same VM then runs an unchanged, pinned Firecracker binary, which boots an
inner Linux guest, runs independent timer ticks and exits successfully. ARM uses
PSCI power-off; x86 requests i8042 reset because Firecracker has no ACPI power-off
device. This is client boot/execution acceptance, not software checkpoint or
migration acceptance. Native x86/ARM CI masks both host virtualization devices,
traces the entire host process tree and retains a digest-bearing report and logs.

The native x86 engine check also cold-restores an outer VM with a running,
unchanged Firecracker and inner Linux guest. With QEMU 10.2.1 and the
`max,svm=on,npt=on,enforce=on` profile, the inner guest reaches an input gate
after tick 0. QMP pauses and saves the outer VM, the source emulator exits,
and a fresh emulator loads that state. Only the restored guest receives the
release token and produces ticks 1 and 2, then both guests shut down. This
verifies nested SVM state continuity in the execution engine. It does not yet
provide checkpoint/restore through the production `flexvm software` lifecycle;
that integration remains tracked in #1358. Both source and target process trees
mask and trace host KVM and vhost-vsock, and panic or duplicate markers fail.

The serial guest agent supports a separate `BARRIER 1` request-admission protocol.
QUIESCE closes admission before waiting for accepted request setup and command
bodies to finish. Long-running commands and output/input attachments release
admission after setup. The dispatcher remains available for PING, FENCE and an
explicit RESUME while a barrier drains. Timeouts leave admission closed; resume
requires the exact saved generation/sequence and the current host fence. A new
owner cannot resume a barrier with request setup still active.

Cold boot probes this capability and, when present, holds admission closed across
its existing QMP pause/resume check. Agents without the capability retain the
foreground path. The initial unfenced owner uses generation/epoch zero;
persistent owners must establish a nonzero FENCE first. Fenced MAINT requests
allow clock, network and hostname setup while public admission remains closed.
The old unversioned QUIESCE remains a filesystem sync/cache operation and cannot
acknowledge this barrier. General mutator deduplication and migration still
require the lifecycle work in #1358.

`flexvm software --name NAME` publishes the foreground VM through the ordinary
name lock and owner control socket. `ps`, `inspect`, argv exec (including guest
credentials, environment and cwd), pause/unpause, `wait` and `kill` use the normal
CLI. Records explicitly identify QEMU TCG and its real process identity and image;
software VMs have no Firecracker template or PID. The VM still ends with its
initial command. `stop` captures a private, verified local snapshot and reaps the
source engine; `start` or `start -a` restores that workload in a fresh owner and
engine. Checkpoints bind the engine, kernel, root filesystem and firmware to their
content digests and preserve the foreground session's delivered offset. A durable
ownership grant prevents implicit replay of a checkpoint that has already run.
An interrupted restore after that grant remains quarantined for explicit recovery.
Native CI checks repeated stop/start, a paused source, detached startup, RAM and
process identity, contiguous output, corrupted-input refusal and blocked-output
kill. Restart policies, checkpoint export/import, cross-host migration and network
connection continuity remain pending. A direct SIGTERM is refused; use `stop` for
suspend or `kill` for destruction. See [the lifecycle contract](software-lifecycle.md).

Named software VMs use serial control and fixed RAM. The initial admission policy
holds a full RAM grant for the VM's lifetime. This is conservative: resident RAM
already reduces MemAvailable, so it may leave extra headroom and reduce packing
density. Elastic memory and accurate shared admission accounting remain work in
#1358. Their address is private to the userspace network, not a routed host address.
The owner and actual engine have distinct verified identities; a hard owner death
terminates the engine through its parent-death signal. Recovery/garbage collection
of private runtime paths after an abrupt death remains part of lifecycle integration.

## Guest kernel module acceptance

`--kernel-sdk` installs the native development bundle matching the selected
kernel. `--kernel-modules FILE` accepts a custom runtime or development bundle
with the same validation. Ordinary images receive the small runtime bundle.

```sh
scripts/fetch.sh --kernel-sdk
sudo scripts/compat/software-modules.py --bin target/release/flexvm \
  --kernel /var/lib/flexvm/artifacts/vmlinux --output /tmp/software-modules
```

The software harness uses the normal CLI to prepare an immutable compiler OCI
image, compiles two modules inside the guest, installs them with kbuild and real
DKMS, checks modprobe dependencies and rejects incompatible vermagic. Its module
creates a random kernel cookie and advances a kernel timer. Both must remain
live through pause and stop/start, with fresh progress after restoration; an
unload/reload must generate a new cookie. Userspace PID, process start time, RAM
and progress are checked independently. Both host virtualization devices are
masked before tracing; host module-loading syscalls must be absent.

Native x86_64 and aarch64 CI run this harness separately and upload reports,
logs and host traces. The accelerated `kernel_modules` E2E case additionally
checks loaded state through suspend/start, checkpoint/restore and migration in
both directions. Modules requiring hardware that the selected engine does not
provide still need that device to be implemented; matching build inputs alone
do not establish device support.
