# Guest KVM provider experiment

The x86 compatibility fixture loads this module into a disposable software VM
with guest SVM and VMX disabled. A PCI shared-memory mailbox with
eventfd-backed doorbells connects it to a parent process that starts a
separate QEMU TCG worker. A standalone Linux KVM
client opens `/dev/kvm`, creates a VM and vCPU, maps `kvm_run`, and gets a port
I/O exit. The client changes a byte in shared RAM and updates the stopped
child's registers, including its instruction pointer. A second `KVM_RUN`
resumes the same child. It uses both updates to produce the next I/O byte.

The module supports one VM, up to two vCPUs and up to eight pinned slots with a
combined limit of 256 MiB. The initial RAM layout stays fixed while the
worker runs.
The parent validates the physical offsets and seals their ordered
layout in a file. Both engines fill one contiguous address interval with
shared mappings of the outer VM RAM and combine consecutive offsets into
one mapping. The parent stops the child before acknowledging
release of the slot. If it cannot confirm release, the pages stay pinned
until the outer VM exits.
The worker supports byte output to one port in x86 real mode, flat
32-bit protected mode, and 64-bit mode with four-level paging.
The client writes general registers through `KVM_SET_REGS` before
and between runs and reads actual worker state through `KVM_GET_REGS`.
After an exit, `KVM_GET_SREGS` also returns live segment caches, descriptor
tables, and control registers. The TCG worker uses private Unix sockets for
debugger and QMP register requests. Memory invalidation, additional x86
CPU state, concurrent vCPU runs, interrupt delivery, and checkpointing remain part of
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
Add `--protected-entry` to set initial x86 protected mode through
`KVM_SET_SREGS` and execute a 32-bit program at 16 MiB.
Use `--protected-entry --ram-pages 49152` to map a 192 MiB slot and verify
child writes to the first, middle, and last pages.
Add `--split-slot` to divide the RAM between slots 0 and 5 at guest
physical addresses 16 MiB and 512 MiB.
Add `--interrupt-run` in protected mode to interrupt a running vCPU three
times with a signal. Each return is acknowledged after the worker stops.
The client checks that shared-memory writes cease on every stop and resume
on subsequent runs, then releases the loop and receives an I/O exit.
Add `--two-vcpus` in protected mode to alternate between two vCPUs in one
worker. The client checks shared RAM, independent register state, and continued
execution of the first vCPU after closing the second vCPU's descriptor.
Add `--long-mode` with at least four pages in the first slot. The client supplies
page tables, enters at a virtual address above 4 GiB, checks the live control
registers and executes a 64-bit transfer between extended registers.
Add `--fpu` to exercise `KVM_GET_FPU` and `KVM_SET_FPU` in long mode. The
client sets an x87 stack value and an XMM register, checks the effect of guest
instructions, then writes new values and checks them after re-entry. The
worker preserves MXCSR as the Linux KVM_FPU ioctl does.
Add `--msrs` in a separate long-mode run to exercise the Linux boot MSR set.
The client reads and writes MSRs from the guest, measures TSC progress, and
checks the completed prefix of batches with an unsupported index. This
fixture supports up to 64 entries per request and returns staged values before
the first run. The worker provides live values after it starts.
Add `--cpuid` in a separate protected-mode run. The client queries the parent
CPU model and configures each vCPU before its first run. With `--two-vcpus`,
the child checks that each CPU sees different results for the same indexed
CPUID function. The TCG worker uses the installed table for its responses
and applies vendor-specific out-of-range behavior. It computes OSXSAVE,
OSPKE, and the active XSAVE area size from the running CPU's state.
Add `--mmio-write` in a separate long-mode run to return MMIO writes from
a device page. The client writes through a virtual alias and checks each
physical address, width and byte sequence. A shared-memory marker shows that
the worker stopped at each exit and continued from the same instruction stream.
Use `--mmio-read` to exercise both writes and reads. The single vCPU stops
at each read. On the next ordinary `KVM_RUN`, it completes the access with
the bytes written by the client into the mapped `kvm_run` page. Completion
with a pending signal and parallel vCPU entry remain part of #1501.
Add `--ioeventfd` to exercise real eventfd notifications on matching MMIO and
port writes. The VM's registry supports address, access width, data matches
and any-length writes. Matching writes signal the eventfd and continue the
same vCPU. The fixture checks that a deassigned write returns to userspace.
The worker uses one host mapping per consecutive extent. Highly fragmented
slots can reach the host's mapping limit. A failed mapping releases the
partially mapped worker span.
