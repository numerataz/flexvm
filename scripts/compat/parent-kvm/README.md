# Guest KVM provider experiment

The x86 compatibility fixture loads this module into a disposable software VM
with guest SVM and VMX disabled. A PCI shared-memory mailbox with
eventfd-backed doorbells connects it to a parent process that starts a
separate QEMU TCG worker. A standalone Linux KVM
client opens `/dev/kvm`, creates a VM and vCPU, maps `kvm_run`, and gets a port
I/O exit. The client changes a byte in shared RAM and updates the stopped
child's registers, including its instruction pointer. A second `KVM_RUN`
resumes the same child. It uses both updates to produce the next I/O byte.

The module supports one VM, one vCPU and one pinned slot of up to 128 4 KiB
pages. The parent validates the physical offsets and seals their ordered
layout in a file. Both engines fill one contiguous address interval with
shared mappings of the outer VM RAM and combine consecutive offsets into
one mapping. The parent stops the child before acknowledging
release of the slot. If it cannot confirm release, the pages stay pinned
until the outer VM exits.
The worker supports byte output to one port and a subset of x86 real-mode
registers. The client writes those registers through `KVM_SET_REGS` before
and between runs and reads actual worker state through `KVM_GET_REGS`.
After an exit, `KVM_GET_SREGS` also returns live segment caches, descriptor
tables, and control registers. The TCG worker uses private Unix sockets for
debugger and QMP register requests. Memory invalidation, protected and long
mode state, interrupts, and checkpointing remain part of
[issue #1501](https://github.com/numerataz/flexvm/issues/1501).

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
Use `--ram-pages 64` to exercise a larger slot. The test checks the worker's
actual address mappings and the child's writes at both ends of the slot.
