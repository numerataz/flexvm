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
the bytes written by the client into the mapped `kvm_run` page. Parallel vCPU
entry remains part of #1501.
Add `--ioeventfd` to exercise real eventfd notifications on matching MMIO and
port writes. The VM's registry supports address, access width, data matches
and any-length writes. Matching writes signal the eventfd and continue the
same vCPU. The fixture checks that a deassigned write returns to userspace.
Add `--irqchip` to a single-vCPU protected-mode run to exercise
`KVM_CREATE_IRQCHIP` and `KVM_IRQ_LINE`. The guest configures the PIC and
interrupt descriptor table and acknowledges the interrupt in its own handler.
This test sets line state between runs.
Add `--pit` to that run to create an i8254 timer with `KVM_CREATE_PIT2`.
The child programs a one-shot tick over port I/O and halts. The timer
interrupt wakes the same vCPU, and the guest acknowledges it before returning
to the VMM. PIT state transfer is tracked in #1501.
Use `--irqfd` in a separate run to route edge-triggered eventfds to the default
x86 GSI lines. A doorbell per line allows native KVM to consume the event
directly and lets the TCG worker pulse its controller during an active run.
The client wakes a halted vCPU, exercises deassignment through a duplicated
descriptor, and registers an eventfd with a signal already pending. Resampling,
custom routes, and snapshot state are tracked in #1501.
Use `--zero-slot --protected-entry --ram-pages 32768` to exercise the 128 MiB
slot used by Firecracker. The guest reads and updates markers at the beginning
and end of the slot, including within the legacy VGA and ROM windows. The
worker maps the registered bytes there and limits VM RAM to addresses below
the reserved 3 GiB device boundary.
Use `--pvh --ram-pages 32768` to exercise that slot with the x86 PVH entry
state from Firecracker. The VMM reads the actual worker reset registers and
sets the GDT, IDT, task selector, and CR0 before entry at GPA `0x1000540`.
The guest records the descriptor and control registers using x86 instructions.
Add `--tss` to reserve the same three-page guest physical range that
Firecracker configures before creating the x86 interrupt controller. Native
KVM receives the exact address. The TCG worker uses the reservation when
validating its RAM slots.
Add `--lapic` to read the reset xAPIC image, stage LINT0 and LINT1 before
the first run, and update the stopped controller. The guest receives a PIC
interrupt through the installed state, then changes LINT1 through MMIO.
The test checks that restoring ICR contents does not send an interrupt.
Use `--vcpu-events --protected-entry` to restore a masked pending NMI,
deliver an exception with its error code and an interrupt, then restore
SMM flags and a nonzero startup vector from the VMM.
Use `--xsave --protected-entry` to verify the standard 4 KiB XSAVE image.
The guest reads the staged and restored x87 control word, MXCSR, and both
halves of YMM0. The VMM also observes guest changes and checks how the
legacy FPU ioctl interacts with the staged XSAVE state.
Use `--xcrs --protected-entry` to stage XCR0, change it in the guest with
XSETBV, and read back a live restore with XGETBV.
Use `--mp-state --protected-entry` to read the startup state, restore the
vCPU to HALTED and keep it stopped until a real IRQ arrives. The fixture
also checks the entry offset after restoring a startup IPI.
Use `--debugregs --protected-entry` to stage a hardware breakpoint,
handle the ensuing debug exception inside the child, and verify the guest's
debug register writes from the stopped VMM.
Add `--pit-state` to stage a timer latch and the speaker state before
execution. The guest consumes the latch and updates the speaker port. The
VMM then restores a live one-shot timer and the interrupt wakes the guest.
Add `--irqchip-state` to read and update the parent PIC and IOAPIC state.
The VMM installs an IOAPIC route before the first run, reads the live PIC
configuration, and verifies that the new IOAPIC route delivers a guest
interrupt. Both parent engines operate on their live controllers.
Add `--pio` to exercise VMM-owned x86 ports. The client gets the port,
direction, width, count, and data in its mapped run area. It supplies bytes
for scalar and repeated input before re-entering the vCPU. The test also
checks that the configured PIC and PIT still handle their own ports.
Add `--pio-boundary` to exercise both sides of a PIC port range and the
top of the x86 port space. The TCG worker classifies the complete CPU
transaction before handing it to a device or to the VMM.
Add `--complete-read` to the MMIO or port fixture to complete an input with
`immediate_exit` set. The client observes the updated result register and
verifies that the next guest instruction waits for ordinary re-entry.
The worker uses one host mapping per consecutive extent. Highly fragmented
slots can reach the host's mapping limit. A failed mapping releases the
partially mapped worker span.
