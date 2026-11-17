# Guest KVM provider experiment

The x86 compatibility fixture loads this module into a disposable software VM
with guest SVM and VMX disabled. A PCI shared-memory mailbox with
eventfd-backed doorbells connects it to a parent process that starts a
separate QEMU TCG worker. A standalone Linux KVM
client opens `/dev/kvm`, creates a VM and vCPU, maps `kvm_run`, and gets a port
I/O exit. A second `KVM_RUN` resumes the same child. The child reads a byte
the client changed while it was paused and reports it on the next I/O exit.

The module supports one VM, one vCPU and one pinned slot of one or two
4 KiB pages. The child maps each page directly from its physical offset in
the outer VM's memory file. The parent stops the child before acknowledging
release of the slot. If it cannot confirm release, the pages stay pinned
until the outer VM exits.
The worker supports byte output to one port with a fixed entry point.
Full register state, memory invalidation, interrupts, and checkpointing
remain part of [issue #1501](https://github.com/numerataz/flexvm/issues/1501).

Run the fixture on x86 with the QEMU build from `scripts/build-qemu.sh` and
the prepared kernel build tree for the selected FlexVM kernel.

```sh
sudo python3 scripts/compat/parent-kvm-run.py \
  --qemu /path/to/qemu-system-x86_64 --kernel /path/to/vmlinux \
  --kernel-build /path/to/kernel/build --output /tmp/parent-kvm-run
```

On a host with working KVM, add `--native-oracle` to run the same client binary
against the host kernel before starting the software-only proof. The report
records first-run and warm re-entry durations. The TCG worker sends the
port byte over its run socket after stopping the vCPU. The guest uses an
MSI-X interrupt to receive the parent's reply.

With `--parent-engine kvm`, the parent runs the child vCPU through the host
KVM device. The guest and client use the same interface and shared page.
The default TCG run masks the host KVM device and exercises software execution.
Add `--ram-pages 1` to run the same client with a single-page slot.
