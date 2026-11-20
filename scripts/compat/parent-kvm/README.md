# Guest KVM provider experiment

The x86 compatibility fixture loads this module into a disposable software VM
with guest SVM and VMX disabled. A PCI shared-memory mailbox with
eventfd-backed doorbells connects it to a parent process that starts a
separate QEMU TCG worker. A standalone Linux KVM
client opens `/dev/kvm`, creates a VM and vCPU, maps `kvm_run`, and gets a port
I/O exit. A second `KVM_RUN` resumes the same child. The child reads a byte
the client changed while it was paused and reports it on the next I/O exit.

The module supports one VM, one vCPU and one pinned 4 KiB RAM page. The
child maps that page directly from the outer VM's memory file. The parent
stops the child before acknowledging release of the page. If it cannot
confirm the release, the page stays pinned until the outer VM exits.
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
records first-run and warm re-entry durations. The parent waits for the QEMU
stop event, and the guest uses an MSI-X interrupt to receive the reply.
