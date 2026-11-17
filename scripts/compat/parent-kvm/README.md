# Guest KVM provider experiment

The x86 compatibility fixture loads this module into a disposable software VM
with guest SVM and VMX disabled. A PCI shared-memory mailbox connects it to a
parent process that starts a separate QEMU TCG worker. A standalone Linux KVM
client opens `/dev/kvm`, creates a VM and vCPU, maps `kvm_run`, and gets a port
I/O exit. The child writes a byte back to the client's registered RAM.

The module supports one VM, one vCPU and one copied 4 KiB RAM region. The
worker executes a single I/O-exit test with a fixed entry point. Full register
state, repeated execution, live memory mappings, interrupts, and checkpointing
remain part of [issue #1501](https://github.com/numerataz/flexvm/issues/1501).

Run the fixture on x86 with a QEMU build that supports sandboxing and the
prepared kernel build tree for the selected FlexVM kernel.

```sh
sudo python3 scripts/compat/parent-kvm-run.py \
  --qemu /path/to/qemu-system-x86_64 --kernel /path/to/vmlinux \
  --kernel-build /path/to/kernel/build --output /tmp/parent-kvm-run
```

On a host with working KVM, add `--native-oracle` to run the same client binary
against the host kernel before starting the software-only proof.
