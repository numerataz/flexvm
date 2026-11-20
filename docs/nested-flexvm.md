# Nested FlexVM CLI acceptance

`software-workload.py` can run the normal native FlexVM CLI inside a software-backed
Linux guest. The outer emulator uses TCG and the host's `/dev/kvm` and
`/dev/vhost-vsock` are masked and traced. The child CLI uses the guest's ordinary
Linux KVM driver under emulated SVM/EL2. This exercises unchanged programs opening
`/dev/kvm`; it does not yet implement the parent-managed provider in issue #1327.

Build a portable guest CLI with the native musl target and `musl-tools` installed:

```sh
arch=$(uname -m)
rustup target add "$arch-unknown-linux-musl"
cargo build --locked --release -p flexvm --target "$arch-unknown-linux-musl"
python3 scripts/compat/nested-flexvm-inputs.py --output /var/tmp/nested-inputs
```

Use the matching verified kernel, runtime modules and Firecracker from the same
artifact directory used by the normal CLI. Prepare the distro image with
`scripts/test-image.py`. The CI workload matrix contains the full invocation:
`nested-flexvm` seeds the static CLI, those three artifacts and `child.tar` into
`/nested-input/`, then runs `workloads/nested-flexvm.sh` in systemd mode.
Each streamed input's SHA-256 is checked inside the guest and recorded in the
report. A seed must be a regular file, at most 256 MiB; the combined limit is
512 MiB. Seed destinations must stay beneath `/nested-input/`.

The guest first creates a real clsact qdisc, a classic BPF direct-action filter
and a plug queue in a private network namespace, including releasing the queue.
It repeats these operations after every outer lifecycle transition. The child
also pauses and unpauses through the normal native CLI.

The child runs the regular `pull`, `run`, `exec` and `ps` commands. Its one-vCPU,
128 MiB template avoids implicit memory hotplug, and the parent has 2048 MiB and
one vCPU. The workload verifies the child's PID, process start time and random
RAM cookie, with fresh counter and monotonic timer progress in every phase:
initial execution, outer pause/unpause and outer stop/start in a fresh emulator.
The outer foreground process and root inode checks remain enabled. The distro
also restores with its exec runtime stopped and completes normal OS poweroff.

This acceptance does not prove accelerated nested-state migration, cross-host
hierarchy migration, shared scheduling or parent-enforced child budgets. It does
not close #1327 or #1358. The explicit one-vCPU outer profile also does not resolve
the separate intermittent two-vCPU x86 software failure in #1401.

## Docker inside nested FlexVM

`scripts/compat/workloads/nested-flexvm-docker.sh` runs stock `docker:27-dind`
inside a nested FlexVM child launched by the static musl `flexvm` CLI inside a
software-backed outer guest (no host `/dev/kvm` or `/dev/vhost-vsock`).

Prepare a local OCI archive of `docker:27-dind` for the target architecture
(under 256 MiB, fitting the `/nested-input/` seed budget) and run
`software-workload.py` with the patched TCG QEMU (`scripts/build-qemu.sh`) and
3072 MiB outer memory:

```sh
skopeo copy --override-os linux --override-arch amd64 \
  docker://docker.io/library/docker:27-dind \
  oci-archive:/var/tmp/docker-dind.tar:docker:27-dind

sudo env PATH="/path/to/patched-qemu/bin:$PATH" \
  python3 scripts/compat/software-workload.py \
  --bin target/release/flexvm \
  --kernel /path/to/artifacts/vmlinux \
  --boot systemd \
  --image /path/to/software-distro-image \
  --workload scripts/compat/workloads/nested-flexvm-docker.sh \
  --mem 3072 --vcpus 1 --timeout 2400 --poweroff-timeout 120 \
  --require virtualization.kvm \
  --seed target/x86_64-unknown-linux-musl/release/flexvm /nested-input/flexvm \
  --seed /path/to/artifacts/firecracker /nested-input/firecracker \
  --seed /path/to/artifacts/vmlinux /nested-input/vmlinux \
  --seed /path/to/artifacts/kernel-modules.tar.gz /nested-input/kernel-modules.tar.gz \
  --seed /var/tmp/docker-dind.tar /nested-input/docker-dind.tar \
  --output /tmp/nested-flexvm-docker-report
```

Inside the outer guest, the workload configures IPv4 forwarding, NAT, and DNS for
the inner VM's TAP, pulls `/nested-input/docker-dind.tar` (`--mem 1024 --max 1024
--plug 0 --vcpus 1`), and verifies Docker 27.5.1 with native `overlay2` on tmpfs,
cgroup v2 limits (`memory.max`, `cpu.max`, `pids.max`), named volumes, bind
mounts, uncached BuildKit image builds, custom bridge DNS, published ports, and
live container continuity (unchanged PID, random RAM cookie, advancing counter,
and HTTP/volume data) across inner `pause`/`unpause`, inner `stop`/`start`,
outer `pause`/`unpause`, outer `stop`/`start` in a fresh emulator, restore
without the runtime service, and clean OS poweroff. Host traces verify zero
`/dev/kvm`, `/dev/vhost-vsock`, or host module-loading accesses.
