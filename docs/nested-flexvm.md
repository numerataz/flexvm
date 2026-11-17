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
