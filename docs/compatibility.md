# General Linux compatibility

The execution tracker is [#1332](https://github.com/numerataz/flexvm/issues/1332).
Each linked issue contains an implementation plan and acceptance criteria.
Support means a workload has passed its real execution and lifecycle tests;
an installed binary or successful capability inventory alone does not establish support.

| Workstream | Ticket | Execution order |
|---|---|---|
| Capability and lifecycle harness | [#1331](https://github.com/numerataz/flexvm/issues/1331) | First: isolated probes, ownership/cleanup, lifecycle state |
| Guest kernel capabilities | [#1330](https://github.com/numerataz/flexvm/issues/1330) | Audit, reproducible kernel/configuration, runtime verification |
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
limits, outbound DNS/HTTP, named volumes, a live container process, and published
ports through each phase:

```sh
sudo scripts/compat.py --memory-mib 16384 \
  --workload scripts/compat/workloads/podman.sh \
  --phases run,suspend,checkpoint --output /tmp/compat-podman
```

Use the migration options above to include migration. This case requires the
expanded guest kernel with FUSE, TUN and container networking enabled. Its
presence here is an executable acceptance case; support status depends on the
recorded results for the tested build and runtime versions.

## Initial audit

The pinned 6.1.155 guest kernel passed the basic namespace, cgroup, overlay,
seccomp, BPF-map, perf, pidfd, memfd, io_uring and legacy iptables probes on an
x86_64 cloud KVM host. FUSE, TUN/TAP and KVM devices were missing; nftables and
conntrack netlink returned `EPROTONOSUPPORT`. Those findings are tracked as
work, not advertised as supported. Root filesystem capacity reporting and
non-root setuid-helper policy also need fixes for ordinary package managers
and rootless runtimes. Future reports must name the tested build and workload
before promoting a workstream's support status.
