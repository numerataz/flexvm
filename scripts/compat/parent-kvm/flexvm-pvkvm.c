// SPDX-License-Identifier: GPL-2.0-only
/*
 * Experimental x86 proof for a KVM client and a parent CPU worker.
 * One VM, pinned RAM slots, serialized vCPUs, and port-output exits.
 */
#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kref.h>
#include <linux/kvm.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <asm/msr-index.h>
#include <asm/processor-flags.h>
#include <asm/fpu/types.h>
#include "mailbox.h"

#define PVKVM_REAL_MODE_FLAGS (X86_EFLAGS_FIXED | X86_EFLAGS_CF | X86_EFLAGS_PF | \
			       X86_EFLAGS_AF | X86_EFLAGS_ZF | X86_EFLAGS_SF | \
			       X86_EFLAGS_IF | X86_EFLAGS_DF | X86_EFLAGS_OF)

#define PVKVM_TSS_SIZE (3 * PAGE_SIZE)

struct pvkvm {
	struct kref refs;
	struct mutex lock;
	struct miscdevice misc;
	void __iomem *mailbox;
	void __iomem *doorbell;
	spinlock_t irqfd_doorbell_lock;
	bool irqfd_doorbell_live;
	wait_queue_head_t replied;
	atomic_t interrupt_count;
	int irq;
	bool dead;
	bool vm_open;
};

struct pvslot {
	struct page **pages;
	u64 gpa;
	unsigned int count;
};

struct pv_ioeventfd {
	struct list_head node;
	struct eventfd_ctx *eventfd;
	u64 address;
	u64 data;
	u32 length;
	bool pio;
	bool datamatch;
};

struct pv_irqfd {
	struct list_head node;
	struct pvvm *vm;
	struct eventfd_ctx *eventfd;
	wait_queue_head_t *head;
	wait_queue_entry_t wait;
	poll_table poll;
	u32 gsi;
	bool closed;
};

struct pvvm {
	struct kref refs;
	struct pvkvm *provider;
	struct mm_struct *owner;
	struct pvslot slots[PVKVM_MAX_SLOTS];
	struct mutex ioevent_lock;
	struct list_head ioevents;
	struct mutex irqfd_lock;
	struct list_head irqfds;
	struct work_struct irqfd_reap;
	unsigned int total_pages;
	bool slots_exposed;
	bool topology_frozen;
	bool irqchip_created;
	bool pit_created;
	bool tss_set;
	u32 tss_gpa;
	unsigned long created_cpus;
	unsigned long open_cpus;
};

struct run_page {
	struct kvm_run run;
	u8 pio[PVKVM_PIO_BYTES] __aligned(PAGE_SIZE);
};

static const u32 boot_msr_indices[] = {
	MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
	MSR_STAR, MSR_CSTAR, MSR_KERNEL_GS_BASE, MSR_SYSCALL_MASK, MSR_LSTAR,
	MSR_IA32_TSC, MSR_IA32_MISC_ENABLE, MSR_MTRRdefType,
};

struct pvcpu {
	struct pvvm *vm;
	struct mutex execution;
	struct run_page *page;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_sregs sregs_reset;
	struct kvm_fpu fpu;
	struct kvm_lapic_state lapic;
	struct pvkvm_cpuid_table *cpuid;
	u64 msrs[ARRAY_SIZE(boot_msr_indices)];
	unsigned long msrs_set;
	unsigned int id;
	unsigned int read_bytes;
	u32 staged_mp_state;
	bool read_pio;
	bool ran;
	bool fpu_set;
	bool lapic_set;
	bool sregs_reset_known;
	bool sregs_set;
	bool staged_sipi_pending;
};

static const struct kvm_sregs reset_sregs = {
	.cs = { .base = 0xffff0000, .limit = 0xffff, .selector = 0xf000, .present = 1 },
};

static bool long_mode(const struct kvm_sregs *sregs)
{
	return sregs->efer & EFER_LMA;
}

static bool valid_protected_entry(const struct kvm_sregs *sregs, const struct kvm_sregs *baseline)
{
	static const struct kvm_segment code = {
		.limit = U32_MAX, .selector = 8, .type = 11, .present = 1,
		.db = 1, .s = 1, .g = 1,
	};
	static const struct kvm_segment data = {
		.limit = U32_MAX, .selector = 16, .type = 3, .present = 1,
		.db = 1, .s = 1, .g = 1,
	};
	static const struct kvm_segment pvh_tr = {
		.limit = 103, .selector = 24, .type = 11, .present = 1,
	};
	struct kvm_sregs wanted = *baseline;
	bool pvh = !long_mode(sregs) && sregs->gdt.limit == 31;

	wanted.cs = code;
	wanted.ds = wanted.es = wanted.fs = wanted.gs = wanted.ss = data;
	wanted.cr0 |= X86_CR0_PE;
	wanted.gdt.limit = 23;
	wanted.gdt.base = sregs->gdt.base;
	if (pvh) {
		wanted.tr = pvh_tr;
		wanted.gdt.limit = 31;
		wanted.idt.base = sregs->idt.base;
		wanted.idt.limit = 7;
		wanted.cr0 = X86_CR0_PE | X86_CR0_ET;
		if (sregs->idt.base > U32_MAX)
			return false;
	}
	if (long_mode(sregs)) {
		wanted.cs.db = 0;
		wanted.cs.l = 1;
		wanted.cr0 |= X86_CR0_PG;
		wanted.cr3 = sregs->cr3;
		wanted.cr4 = X86_CR4_PAE;
		wanted.efer = EFER_LME | EFER_LMA;
		if (!IS_ALIGNED(sregs->cr3, PAGE_SIZE))
			return false;
	}
	return !memcmp(sregs, &wanted, sizeof(wanted)) && sregs->gdt.base <= U32_MAX;
}

static bool valid_real_entry(const struct kvm_sregs *sregs, const struct kvm_sregs *baseline)
{
	struct kvm_sregs wanted = *baseline;

	wanted.cs.base = 0;
	wanted.cs.selector = 0;
	return !memcmp(sregs, &wanted, sizeof(wanted));
}

static bool registers_fit_mode(const struct kvm_regs *regs, const struct kvm_sregs *sregs)
{
	if (long_mode(sregs))
		return true;
	return (regs->rax | regs->rbx | regs->rcx | regs->rdx | regs->rsi | regs->rdi |
		regs->rsp | regs->rbp | regs->rip) <= U32_MAX &&
	       !(regs->r8 | regs->r9 | regs->r10 | regs->r11 | regs->r12 | regs->r13 |
		 regs->r14 | regs->r15);
}

static void publish_slots(void __iomem *mailbox, const struct pvvm *vm)
{
	unsigned int id, count = 0, page = 0;

	for (id = 0; id < PVKVM_MAX_SLOTS; id++) {
		const struct pvslot *slot = &vm->slots[id];
		void __iomem *record;
		unsigned int index;

		if (!slot->count)
			continue;
		record = mailbox + PVKVM_SLOT_TABLE_AT + count * PVKVM_SLOT_RECORD_SIZE;
		writel(id, record);
		writel(slot->count, record + 4);
		writel(lower_32_bits(slot->gpa), record + 8);
		writel(upper_32_bits(slot->gpa), record + 12);
		count++;
		for (index = 0; index < slot->count; index++, page++) {
			u64 address = PFN_PHYS(page_to_pfn(slot->pages[index]));
			void __iomem *entry = mailbox + PVKVM_RAM_ADDRESS_AT + page * sizeof(u64);

			writel(lower_32_bits(address), entry);
			writel(upper_32_bits(address), entry + sizeof(u32));
		}
	}
	writel(count, mailbox + PVKVM_SLOT_COUNT_AT);
}

/* The device lock serializes mailbox use, including close and PCI teardown. */
static int request(struct pvkvm *provider, enum pvkvm_command command,
		   const struct pvvm *memory,
		   struct pvkvm_run_exit *exit)
{
	void __iomem *m = provider->mailbox;
	u32 before, seq;
	long waited;
	int status, interrupts;
	unsigned int pages = memory ? memory->total_pages : 0;

	if (provider->dead)
		return -ENODEV;
	before = readl(m + PVKVM_REQUEST_AT);
	if (readl(m + PVKVM_REPLY_AT) != before) {
		provider->dead = true;
		return -EIO;
	}
	seq = before + 1;
	interrupts = atomic_read(&provider->interrupt_count);
	if (memory)
		publish_slots(m, memory);
	writel(pages * PAGE_SIZE, m + PVKVM_DATA_SIZE_AT);
	writel(command, m + PVKVM_COMMAND_AT);
	wmb();
	writel(seq, m + PVKVM_REQUEST_AT);
	writel(PVKVM_HOST_VECTOR, provider->doorbell + PVKVM_DOORBELL_AT);
	if (command == PVKVM_RUN) {
		waited = wait_event_interruptible(provider->replied,
				atomic_read(&provider->interrupt_count) != interrupts &&
				readl(m + PVKVM_REPLY_AT) == seq);
		if (!waited)
			waited = 1;
	} else if (command == PVKVM_GET_REGS || command == PVKVM_GET_SREGS) {
		waited = wait_event_interruptible_timeout(provider->replied,
				atomic_read(&provider->interrupt_count) != interrupts &&
				readl(m + PVKVM_REPLY_AT) == seq, 5 * HZ);
	} else {
		waited = wait_event_timeout(provider->replied,
				atomic_read(&provider->interrupt_count) != interrupts &&
				readl(m + PVKVM_REPLY_AT) == seq, 5 * HZ);
	}
	if (command == PVKVM_RUN && waited < 0) {
		/* A signal must stop the exact pending run before returning to
		 * userspace. A concurrently completed I/O exit can still win.
		 */
		if (readl(m + PVKVM_REPLY_AT) != seq) {
			writel(seq, m + PVKVM_CANCEL_AT);
			wmb();
			writel(PVKVM_CANCEL_VECTOR, provider->doorbell + PVKVM_DOORBELL_AT);
		}
		waited = wait_event_timeout(provider->replied,
				atomic_read(&provider->interrupt_count) != interrupts &&
				readl(m + PVKVM_REPLY_AT) == seq, 5 * HZ);
	}
	if (waited <= 0) {
		/* The parent can still finish the request. A fresh provider
		 * must use a fresh mailbox.
		 */
		provider->dead = true;
		return waited ? -EINTR : -ETIMEDOUT;
	}
	rmb();
	status = (s32)readl(m + PVKVM_STATUS_AT);
	if (status > 0 || status < -MAX_ERRNO) {
		provider->dead = true;
		return -EIO;
	}
	if (!status && exit)
		memcpy_fromio(exit, m + PVKVM_EXIT_AT, sizeof(*exit));
	return status;
}

static bool close_object(struct pvkvm *p, enum pvkvm_command command)
{
	if (!request(p, command, 0, NULL))
		return true;
	p->dead = true;
	return false;
}

static int request_for_cpu(struct pvcpu *cpu, enum pvkvm_command command,
			   const struct pvvm *memory, struct pvkvm_run_exit *output)
{
	struct pvkvm *p = cpu->vm->provider;

	if (p->dead)
		return -ENODEV;
	writel(cpu->id, p->mailbox + PVKVM_CPU_AT);
	return request(p, command, memory, output);
}

static void provider_free(struct kref *ref)
{
	kfree(container_of(ref, struct pvkvm, refs));
}

static void release_ioeventfd(struct pv_ioeventfd *entry)
{
	eventfd_ctx_put(entry->eventfd);
	kfree(entry);
}

static void signal_irqfd(struct pv_irqfd *entry)
{
	struct pvkvm *p = entry->vm->provider;
	unsigned long flags;
	u64 count;

	lockdep_assert_held(&entry->head->lock);
	eventfd_ctx_do_read(entry->eventfd, &count);
	if (!count || READ_ONCE(entry->closed))
		return;
	spin_lock_irqsave(&p->irqfd_doorbell_lock, flags);
	if (p->irqfd_doorbell_live)
		writel(PVKVM_IRQFD_VECTOR + entry->gsi, p->doorbell + PVKVM_DOORBELL_AT);
	spin_unlock_irqrestore(&p->irqfd_doorbell_lock, flags);
}

static int wake_irqfd(wait_queue_entry_t *wait, unsigned int mode, int sync, void *key)
{
	struct pv_irqfd *entry = container_of(wait, struct pv_irqfd, wait);
	__poll_t events = key_to_poll(key);

	if (events & EPOLLIN)
		signal_irqfd(entry);
	if (events & EPOLLHUP) {
		WRITE_ONCE(entry->closed, true);
		schedule_work(&entry->vm->irqfd_reap);
	}
	return !!(events & EPOLLIN);
}

static void queue_irqfd(struct file *file, wait_queue_head_t *head, poll_table *poll)
{
	struct pv_irqfd *entry = container_of(poll, struct pv_irqfd, poll);

	entry->head = head;
	add_wait_queue_priority(head, &entry->wait);
}

static void release_irqfd(struct pv_irqfd *entry)
{
	u64 count;

	list_del(&entry->node);
	eventfd_ctx_remove_wait_queue(entry->eventfd, &entry->wait, &count);
	eventfd_ctx_put(entry->eventfd);
	kfree(entry);
}

static void reap_irqfds(struct work_struct *work)
{
	struct pvvm *vm = container_of(work, struct pvvm, irqfd_reap);
	struct pv_irqfd *entry, *next;

	mutex_lock(&vm->irqfd_lock);
	list_for_each_entry_safe(entry, next, &vm->irqfds, node) {
		if (READ_ONCE(entry->closed))
			release_irqfd(entry);
	}
	mutex_unlock(&vm->irqfd_lock);
}

static void vm_free(struct kref *ref)
{
	struct pvvm *vm = container_of(ref, struct pvvm, refs);
	struct pvkvm *p = vm->provider;
	bool closed;
	unsigned int id;
	struct pv_ioeventfd *entry, *next;
	struct pv_irqfd *irqfd, *next_irqfd;

	mutex_lock(&vm->irqfd_lock);
	list_for_each_entry_safe(irqfd, next_irqfd, &vm->irqfds, node)
		release_irqfd(irqfd);
	mutex_unlock(&vm->irqfd_lock);
	cancel_work_sync(&vm->irqfd_reap);
	mutex_lock(&p->lock);
	closed = close_object(p, PVKVM_CLOSE_VM);
	p->vm_open = false;
	mutex_unlock(&p->lock);
	if (!closed && vm->slots_exposed)
		pr_warn("flexvm-pvkvm: retaining registered RAM until the enclosing VM exits\n");
	for (id = 0; id < PVKVM_MAX_SLOTS; id++) {
		const struct pvslot *slot = &vm->slots[id];

		if (!slot->count)
			continue;
		if (closed || !vm->slots_exposed)
			unpin_user_pages_dirty_lock(slot->pages, slot->count, true);
		kvfree(slot->pages);
	}
	list_for_each_entry_safe(entry, next, &vm->ioevents, node) {
		list_del(&entry->node);
		release_ioeventfd(entry);
	}
	kref_put(&p->refs, provider_free);
	mmdrop(vm->owner);
	kfree(vm);
}

static int vm_release(struct inode *inode, struct file *file)
{
	struct pvvm *vm = file->private_data;

	kref_put(&vm->refs, vm_free);
	return 0;
}

static int cpu_release(struct inode *inode, struct file *file)
{
	struct pvcpu *cpu = file->private_data;
	struct pvvm *vm = cpu->vm;
	struct pvkvm *p = vm->provider;

	mutex_lock(&p->lock);
	vm->open_cpus &= ~BIT(cpu->id);
	if (request_for_cpu(cpu, PVKVM_CLOSE_VCPU, NULL, NULL))
		p->dead = true;
	else if (!vm->open_cpus)
		vm->slots_exposed = false;
	mutex_unlock(&p->lock);
	kref_put(&vm->refs, vm_free);
	vfree(cpu->page);
	kfree(cpu->cpuid);
	kfree(cpu);
	return 0;
}

static int cpu_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct pvcpu *cpu = file->private_data;

	if (cpu->vm->owner != current->mm)
		return -EIO;
	if (vma->vm_pgoff || vma->vm_end - vma->vm_start != sizeof(*cpu->page) ||
	    !(vma->vm_flags & VM_SHARED) || (vma->vm_flags & VM_EXEC))
		return -EINVAL;
	vma->vm_flags &= ~VM_MAYEXEC;
	return remap_vmalloc_range(vma, cpu->page, 0);
}

static bool slot_contains(const struct pvvm *vm, u64 gpa, unsigned int size)
{
	unsigned int id;

	for (id = 0; id < PVKVM_MAX_SLOTS; id++) {
		const struct pvslot *slot = &vm->slots[id];
		u64 bytes = slot->count * PAGE_SIZE;

		if (size <= bytes && gpa >= slot->gpa && gpa - slot->gpa <= bytes - size)
			return true;
	}
	return false;
}

static void publish_initial_msrs(struct pvcpu *cpu)
{
	void __iomem *mailbox = cpu->vm->provider->mailbox + PVKVM_MSR_AT;
	unsigned int id, count = 0;

	for_each_set_bit(id, &cpu->msrs_set, ARRAY_SIZE(boot_msr_indices)) {
		const struct kvm_msr_entry entry = {
			.index = boot_msr_indices[id], .data = cpu->msrs[id],
		};

		memcpy_toio(mailbox + offsetof(struct pvkvm_msr_batch, entries) + count * sizeof(entry),
			    &entry, sizeof(entry));
		count++;
	}
	writel(count, mailbox);
	writel(0, mailbox + sizeof(u32));
}

static bool signal_ioeventfd(struct pvvm *vm, const struct pvkvm_run_exit *exit)
{
	struct pv_ioeventfd *entry;
	u64 value = 0;
	bool handled = false;

	if (!exit->is_write)
		return false;
	memcpy(&value, exit->data, exit->length);
	mutex_lock(&vm->ioevent_lock);
	list_for_each_entry(entry, &vm->ioevents, node) {
		if (entry->pio != (exit->reason == KVM_EXIT_IO) ||
		    entry->address != exit->address ||
		    (entry->length && entry->length != exit->length) ||
		    (entry->datamatch && entry->data != value))
			continue;
		eventfd_signal(entry->eventfd, 1);
		handled = true;
		break;
	}
	mutex_unlock(&vm->ioevent_lock);
	return handled;
}

enum { PVKVM_IOEVENT_HANDLED = 1 };

static int complete_run(struct pvcpu *cpu, const struct pvkvm_run_exit *exit)
{
	struct pvkvm *p = cpu->vm->provider;
	struct run_page *page = cpu->page;
	unsigned int bytes;

	if (exit->is_write > 1 || !exit->count)
		return -EIO;
	if (!exit->is_write && hweight_long(cpu->vm->open_cpus) > 1)
		return -EOPNOTSUPP;
	switch (exit->reason) {
	case KVM_EXIT_IO:
		if (!is_power_of_2(exit->length) || exit->length > 4 ||
		    exit->address > U16_MAX || exit->count > sizeof(page->pio) / exit->length)
			return -EIO;
		if (exit->count == 1 && signal_ioeventfd(cpu->vm, exit))
			return PVKVM_IOEVENT_HANDLED;
		bytes = exit->length * exit->count;
		if (exit->is_write) {
			memcpy_fromio(page->pio, p->mailbox + PVKVM_PIO_DATA_AT, bytes);
		} else {
			memset(page->pio, 0, bytes);
			cpu->read_bytes = bytes;
			cpu->read_pio = true;
		}
		page->run.io.direction = exit->is_write ? KVM_EXIT_IO_OUT : KVM_EXIT_IO_IN;
		page->run.io.size = exit->length;
		page->run.io.port = exit->address;
		page->run.io.count = exit->count;
		page->run.io.data_offset = offsetof(struct run_page, pio);
		break;
	case KVM_EXIT_MMIO:
		if (!is_power_of_2(exit->length) || exit->length > sizeof(exit->data) || exit->count != 1)
			return -EIO;
		if (signal_ioeventfd(cpu->vm, exit))
			return PVKVM_IOEVENT_HANDLED;
		page->run.mmio.phys_addr = exit->address;
		memset(page->run.mmio.data, 0, sizeof(page->run.mmio.data));
		if (exit->is_write)
			memcpy(page->run.mmio.data, exit->data, exit->length);
		else {
			cpu->read_bytes = exit->length;
			cpu->read_pio = false;
		}
		page->run.mmio.len = exit->length;
		page->run.mmio.is_write = exit->is_write;
		break;
	default:
		return -EIO;
	}
	page->run.exit_reason = exit->reason;
	return 0;
}

static void publish_read_completion(struct pvcpu *cpu)
{
	struct pvkvm *p = cpu->vm->provider;
	struct pvkvm_read_completion completion = { .length = cpu->read_bytes };

	if (completion.length && cpu->read_pio)
		memcpy_toio(p->mailbox + PVKVM_PIO_DATA_AT, cpu->page->pio, completion.length);
	else if (completion.length)
		memcpy(completion.data, cpu->page->run.mmio.data, completion.length);
	memcpy_toio(p->mailbox + PVKVM_COMPLETION_AT, &completion, sizeof(completion));
}

static int finish_interrupted_read(struct pvcpu *cpu)
{
	int result;

	if (!cpu->read_bytes)
		return -EINTR;
	publish_read_completion(cpu);
	result = request_for_cpu(cpu, PVKVM_COMPLETE_READ, NULL, NULL);
	if (result)
		return result;
	cpu->read_bytes = 0;
	return -EINTR;
}

static int run_cpu(struct pvcpu *cpu)
{
	struct pvvm *vm = cpu->vm;
	struct pvkvm *p = vm->provider;
	const struct pvvm *memory;
	struct pvkvm_run_exit exit;
	int result;

	result = cpu->read_bytes ? mutex_lock_killable(&p->lock) : mutex_lock_interruptible(&p->lock);
	if (result)
		return -EINTR;
	if (p->dead) {
		result = -ENODEV;
		goto unlock;
	}
	if (READ_ONCE(cpu->page->run.immediate_exit) || signal_pending(current)) {
		result = finish_interrupted_read(cpu);
		goto unlock;
	}
	if (!cpu->ran && !long_mode(&cpu->sregs) && !slot_contains(vm, cpu->regs.rip, 1)) {
		result = -EINVAL;
		goto unlock;
	}
	if (!cpu->ran && (cpu->sregs.cr0 & X86_CR0_PE) &&
	    !slot_contains(vm, cpu->sregs.gdt.base, cpu->sregs.gdt.limit + 1)) {
		result = -EINVAL;
		goto unlock;
	}
	if (!cpu->ran && cpu->sregs.gdt.limit == 31 &&
	    !slot_contains(vm, cpu->sregs.idt.base, cpu->sregs.idt.limit + 1)) {
		result = -EINVAL;
		goto unlock;
	}
	if (!cpu->ran && long_mode(&cpu->sregs) && !slot_contains(vm, cpu->sregs.cr3, PAGE_SIZE)) {
		result = -EINVAL;
		goto unlock;
	}
	memory = vm->slots_exposed ? NULL : vm;
	vm->slots_exposed = true;
	vm->topology_frozen = true;
	if (!cpu->ran) {
		memcpy_toio(p->mailbox + PVKVM_REGISTERS_AT, &cpu->regs, sizeof(cpu->regs));
		memcpy_toio(p->mailbox + PVKVM_INITIAL_SREGISTERS_AT, &cpu->sregs, sizeof(cpu->sregs));
		writel(cpu->fpu_set, p->mailbox + PVKVM_FPU_VALID_AT);
		if (cpu->fpu_set)
			memcpy_toio(p->mailbox + PVKVM_FPU_AT, &cpu->fpu, sizeof(cpu->fpu));
		writel(cpu->lapic_set, p->mailbox + PVKVM_LAPIC_VALID_AT);
		if (cpu->lapic_set)
			memcpy_toio(p->mailbox + PVKVM_LAPIC_AT, &cpu->lapic, sizeof(cpu->lapic));
		publish_initial_msrs(cpu);
		writel(!!cpu->cpuid, p->mailbox + PVKVM_CPUID_VALID_AT);
		if (cpu->cpuid)
			memcpy_toio(p->mailbox + PVKVM_CPUID_AT, cpu->cpuid,
				    offsetof(struct pvkvm_cpuid_table, entries) +
				    cpu->cpuid->count * sizeof(cpu->cpuid->entries[0]));
	}
	do {
		publish_read_completion(cpu);
		result = request_for_cpu(cpu, PVKVM_RUN, memory, &exit);
		if (!result || result == -EINTR) {
			cpu->ran = true;
			cpu->read_bytes = 0;
		}
		if (result)
			break;
		result = complete_run(cpu, &exit);
		if (result < 0)
			p->dead = true;
		if (result == PVKVM_IOEVENT_HANDLED &&
		    (READ_ONCE(cpu->page->run.immediate_exit) || signal_pending(current)))
			result = -EINTR;
		memory = NULL;
	} while (result == PVKVM_IOEVENT_HANDLED);
unlock:
	mutex_unlock(&p->lock);
	return result;
}

static int read_stopped_registers(struct pvcpu *cpu, enum pvkvm_command command,
				  unsigned int offset, void *registers, size_t size)
{
	struct pvkvm *p = cpu->vm->provider;
	int result = mutex_lock_interruptible(&p->lock);

	if (result)
		return result;
	result = request_for_cpu(cpu, command, NULL, NULL);
	if (!result)
		memcpy_fromio(registers, p->mailbox + offset, size);
	mutex_unlock(&p->lock);
	return result;
}

static int write_stopped_registers(struct pvcpu *cpu, enum pvkvm_command command,
				   unsigned int offset, const void *registers, size_t size)
{
	struct pvkvm *p = cpu->vm->provider;
	int result = mutex_lock_interruptible(&p->lock);

	if (result)
		return result;
	if (p->dead) {
		result = -ENODEV;
	} else {
		memcpy_toio(p->mailbox + offset, registers, size);
		result = request_for_cpu(cpu, command, NULL, NULL);
	}
	mutex_unlock(&p->lock);
	return result;
}

static int boot_msr_index(u32 msr)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(boot_msr_indices); i++)
		if (boot_msr_indices[i] == msr)
			return i;
	return -1;
}

static bool valid_msr_value(u32 msr, u64 value)
{
	switch (msr) {
	case MSR_IA32_SYSENTER_CS:
		return value <= U16_MAX;
	case MSR_IA32_MISC_ENABLE:
		return value <= 1;
	case MSR_SYSCALL_MASK:
		return value <= U32_MAX;
	case MSR_MTRRdefType:
		return value == 0 || value == 0x806;
	case MSR_IA32_SYSENTER_ESP:
	case MSR_IA32_SYSENTER_EIP:
	case MSR_CSTAR:
	case MSR_LSTAR:
	case MSR_KERNEL_GS_BASE:
		return (s64)(value << 16) >> 16 == (s64)value;
	default:
		return true;
	}
}

static long stopped_msr_batch(struct pvcpu *cpu, struct pvkvm_msr_batch *batch, bool write)
{
	struct pvkvm *p = cpu->vm->provider;
	void __iomem *mailbox = p->mailbox + PVKVM_MSR_AT;
	unsigned int offered = batch->count;
	int result = mutex_lock_interruptible(&p->lock);

	if (result)
		return result;
	if (p->dead) {
		result = -ENODEV;
		goto unlock;
	}
	memcpy_toio(mailbox, batch, offsetof(struct pvkvm_msr_batch, entries) + offered * sizeof(batch->entries[0]));
	result = request_for_cpu(cpu, write ? PVKVM_SET_MSRS : PVKVM_GET_MSRS, NULL, NULL);
	if (result)
		goto unlock;
	batch->count = readl(mailbox);
	if (batch->count > offered) {
		p->dead = true;
		result = -EIO;
	} else if (!write) {
		memcpy_fromio(batch->entries, mailbox + offsetof(struct pvkvm_msr_batch, entries),
			      batch->count * sizeof(batch->entries[0]));
	}
unlock:
	mutex_unlock(&p->lock);
	return result;
}

static long cpu_msrs(struct pvcpu *cpu, bool write, struct kvm_msrs __user *user)
{
	struct pvkvm_msr_batch *batch;
	unsigned int count, i;
	long result;

	if (get_user(count, &user->nmsrs))
		return -EFAULT;
	if (count > PVKVM_MSR_BATCH_MAX)
		return -E2BIG;
	if (!count)
		return 0;
	batch = kzalloc(sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return -ENOMEM;
	if (copy_from_user(batch->entries, user->entries, count * sizeof(batch->entries[0]))) {
		result = -EFAULT;
		goto out;
	}
	for (i = 0; i < count; i++) {
		struct kvm_msr_entry *entry = &batch->entries[i];
		int id = boot_msr_index(entry->index);

		if (id < 0 || (write && !valid_msr_value(entry->index, entry->data)))
			break;
		entry->reserved = 0;
		if (cpu->ran)
			continue;
		if (write) {
			cpu->msrs[id] = entry->data;
			set_bit(id, &cpu->msrs_set);
		} else if (test_bit(id, &cpu->msrs_set)) {
			entry->data = cpu->msrs[id];
		} else {
			break;
		}
	}
	batch->count = i;
	if (cpu->ran && batch->count) {
		result = stopped_msr_batch(cpu, batch, write);
		if (result)
			goto out;
	}
	result = batch->count;
	if (!write && copy_to_user(user->entries, batch->entries, batch->count * sizeof(batch->entries[0])))
		result = -EFAULT;
out:
	kfree(batch);
	return result;
}

static long copy_cpuid(struct kvm_cpuid2 __user *user,
		       const struct pvkvm_cpuid_table *table, u32 capacity)
{
	u32 count = table ? table->count : 0;

	if (capacity < count)
		return -E2BIG;
	if (count && copy_to_user(user->entries, table->entries, count * sizeof(table->entries[0])))
		return -EFAULT;
	return put_user(count, &user->nent) ? -EFAULT : 0;
}

static bool valid_cpuid_table(const struct pvkvm_cpuid_table *table)
{
	unsigned int i, j;

	for (i = 0; i < table->count; i++) {
		const struct kvm_cpuid_entry2 *entry = &table->entries[i];

		if (entry->flags & ~KVM_CPUID_FLAG_SIGNIFCANT_INDEX ||
		    entry->padding[0] || entry->padding[1] || entry->padding[2])
			return false;
		for (j = 0; j < i; j++) {
			const struct kvm_cpuid_entry2 *prior = &table->entries[j];

			if (entry->function == prior->function &&
			    (!(entry->flags & prior->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) ||
			     entry->index == prior->index))
				return false;
		}
	}
	return true;
}

static long cpu_cpuid(struct pvcpu *cpu, bool write, struct kvm_cpuid2 __user *user)
{
	struct pvkvm_cpuid_table *table;
	u32 count;
	size_t bytes;
	long result = 0;

	if (get_user(count, &user->nent))
		return -EFAULT;
	if (!write)
		return copy_cpuid(user, cpu->cpuid, count);
	if (count > PVKVM_CPUID_MAX)
		return -E2BIG;
	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return -ENOMEM;
	table->count = count;
	bytes = count * sizeof(table->entries[0]);
	if (copy_from_user(table->entries, user->entries, bytes))
		result = -EFAULT;
	else if (!valid_cpuid_table(table))
		result = -EINVAL;
	else if (cpu->ran && (!cpu->cpuid || cpu->cpuid->count != count ||
			      memcmp(cpu->cpuid->entries, table->entries, bytes)))
		result = -EBUSY;
	else
		swap(cpu->cpuid, table);
	kfree(table);
	return result;
}

static int read_reset_sregs(struct pvcpu *cpu)
{
	int result;

	if (cpu->sregs_reset_known)
		return 0;
	result = read_stopped_registers(cpu, PVKVM_GET_SREGS, PVKVM_REGISTERS_AT,
					&cpu->sregs_reset, sizeof(cpu->sregs_reset));
	if (!result)
		cpu->sregs_reset_known = true;
	return result;
}

static long cpu_lapic(struct pvcpu *cpu, bool write, void __user *user)
{
	struct kvm_lapic_state *record;
	int result = 0;

	if (!READ_ONCE(cpu->vm->irqchip_created))
		return -EINVAL;
	if (!write) {
		if (cpu->ran || !cpu->lapic_set)
			result = read_stopped_registers(cpu, PVKVM_GET_LAPIC, PVKVM_LAPIC_AT,
							&cpu->lapic, sizeof(cpu->lapic));
		if (result)
			return result;
		return copy_to_user(user, &cpu->lapic, sizeof(cpu->lapic)) ? -EFAULT : 0;
	}
	record = memdup_user(user, sizeof(*record));
	if (IS_ERR(record))
		return PTR_ERR(record);
	if (cpu->ran) {
		result = write_stopped_registers(cpu, PVKVM_SET_LAPIC, PVKVM_LAPIC_AT,
						 record, sizeof(*record));
	} else {
		cpu->lapic = *record;
		cpu->lapic_set = true;
	}
	kfree(record);
	return result;
}

static long cpu_debugregs(struct pvcpu *cpu, bool write, struct kvm_debugregs __user *user)
{
	struct kvm_debugregs state;
	int result;

	if (write) {
		if (copy_from_user(&state, user, sizeof(state)))
			return -EFAULT;
		if (state.flags || state.dr6 > U32_MAX || state.dr7 > U32_MAX)
			return -EINVAL;
		memset(state.reserved, 0, sizeof(state.reserved));
		return write_stopped_registers(cpu, PVKVM_SET_DEBUGREGS, PVKVM_DEBUGREGS_AT,
					       &state, sizeof(state));
	}
	result = read_stopped_registers(cpu, PVKVM_GET_DEBUGREGS, PVKVM_DEBUGREGS_AT,
					&state, sizeof(state));
	if (!result && copy_to_user(user, &state, sizeof(state)))
		return -EFAULT;
	return result;
}

static long cpu_mp_state(struct pvcpu *cpu, bool write, struct kvm_mp_state __user *user)
{
	struct kvm_mp_state state;
	int result;

	if (write) {
		if (copy_from_user(&state, user, sizeof(state)))
			return -EFAULT;
		if (state.mp_state != KVM_MP_STATE_RUNNABLE &&
		    (!READ_ONCE(cpu->vm->irqchip_created) ||
		     (state.mp_state > KVM_MP_STATE_SIPI_RECEIVED &&
		      state.mp_state != KVM_MP_STATE_AP_RESET_HOLD)))
			return -EINVAL;
		result = write_stopped_registers(cpu, PVKVM_SET_MP_STATE, PVKVM_MP_STATE_AT,
						 &state, sizeof(state));
		if (!result && !cpu->ran) {
			cpu->staged_mp_state = state.mp_state;
			if (state.mp_state == KVM_MP_STATE_SIPI_RECEIVED)
				cpu->staged_sipi_pending = true;
		}
		return result;
	}
	result = read_stopped_registers(cpu, PVKVM_GET_MP_STATE, PVKVM_MP_STATE_AT,
					&state, sizeof(state));
	if (!result && !cpu->ran && cpu->staged_sipi_pending) {
		/* A pre-run query can consume the SIPI with its reset vector. */
		if (state.mp_state == KVM_MP_STATE_RUNNABLE &&
		    (cpu->staged_mp_state == KVM_MP_STATE_INIT_RECEIVED ||
		     cpu->staged_mp_state == KVM_MP_STATE_SIPI_RECEIVED)) {
			cpu->regs.rip = 0;
			cpu->sregs.cs.base = 0;
			cpu->sregs.cs.selector = 0;
		}
		cpu->staged_sipi_pending = false;
	}
	if (!result && copy_to_user(user, &state, sizeof(state)))
		return -EFAULT;
	return result;
}

/* Serialized with KVM_SET_CPUID2 by cpu_ioctl's execution mutex. */
static u64 guest_xcr0_mask(const struct pvcpu *cpu)
{
	u64 allowed = XFEATURE_MASK_FP;
	unsigned int i;

	if (cpu->cpuid) {
		for (i = 0; i < cpu->cpuid->count; i++) {
			const struct kvm_cpuid_entry2 *entry = &cpu->cpuid->entries[i];

			if (entry->function == 0xd && entry->index == 0) {
				allowed |= entry->eax | ((u64)entry->edx << 32);
				break;
			}
		}
	}
	return allowed;
}

static bool valid_xcr0(const struct pvcpu *cpu, u64 value)
{
	return (value & XFEATURE_MASK_FP) && !(value & ~guest_xcr0_mask(cpu)) &&
	       (!(value & XFEATURE_MASK_YMM) || (value & XFEATURE_MASK_SSE)) &&
	       (!!(value & XFEATURE_MASK_BNDREGS) == !!(value & XFEATURE_MASK_BNDCSR)) &&
	       (!(value & XFEATURE_MASK_AVX512) ||
		((value & XFEATURE_MASK_AVX512) == XFEATURE_MASK_AVX512 && (value & XFEATURE_MASK_YMM))) &&
	       (!(value & XFEATURE_MASK_XTILE) || (value & XFEATURE_MASK_XTILE) == XFEATURE_MASK_XTILE);
}

static long cpu_xcrs(struct pvcpu *cpu, bool write, struct kvm_xcrs __user *user)
{
	struct kvm_xcrs state;
	unsigned int i;
	int result;

	if (write) {
		if (copy_from_user(&state, user, sizeof(state)))
			return -EFAULT;
		if (state.flags || state.nr_xcrs > ARRAY_SIZE(state.xcrs))
			return -EINVAL;
		for (i = 0; i < state.nr_xcrs; i++) {
			struct kvm_xcr xcr = state.xcrs[i];

			if (xcr.xcr)
				continue;
			if (!valid_xcr0(cpu, xcr.value))
				return -EINVAL;
			/* Linux uses the first XCR0 entry, including when a later one repeats it. */
			memset(&state, 0, sizeof(state));
			state.nr_xcrs = 1;
			state.xcrs[0].value = xcr.value;
			return write_stopped_registers(cpu, PVKVM_SET_XCRS, PVKVM_XCRS_AT,
						       &state, sizeof(state));
		}
		/* The x86 KVM ioctl ignores unsupported XCR indices. */
		return 0;
	}
	result = read_stopped_registers(cpu, PVKVM_GET_XCRS, PVKVM_XCRS_AT,
					&state, sizeof(state));
	if (!result && copy_to_user(user, &state, sizeof(state)))
		return -EFAULT;
	return result;
}

static u64 guest_xsave_mask(const struct pvcpu *cpu)
{
	u64 fits = XFEATURE_MASK_FP | XFEATURE_MASK_SSE;
	unsigned int i;

	if (cpu->cpuid) {
		for (i = 0; i < cpu->cpuid->count; i++) {
			const struct kvm_cpuid_entry2 *entry = &cpu->cpuid->entries[i];

			if (entry->function == 0xd && entry->index >= 2 && entry->index < 64 &&
			    entry->ebx >= sizeof(struct xregs_state) && entry->ebx < PVKVM_XSAVE_BYTES &&
			    entry->eax && entry->eax <= PVKVM_XSAVE_BYTES - entry->ebx)
				fits |= BIT_ULL(entry->index);
		}
	}
	return fits & (guest_xcr0_mask(cpu) | XFEATURE_MASK_SSE);
}

static void apply_fpu_to_xsave(struct xregs_state *record, const struct kvm_fpu *fpu)
{
	/* KVM_SET_FPU updates the legacy registers without changing XSTATE_BV. */
	if (record->header.xfeatures & XFEATURE_MASK_FP) {
		record->i387.cwd = fpu->fcw;
		record->i387.swd = fpu->fsw;
		record->i387.twd = fpu->ftwx;
		record->i387.fop = fpu->last_opcode;
		record->i387.rip = fpu->last_ip;
		record->i387.rdp = fpu->last_dp;
		memcpy(record->i387.st_space, fpu->fpr, sizeof(fpu->fpr));
	}
	if (record->header.xfeatures & XFEATURE_MASK_SSE)
		memcpy(record->i387.xmm_space, fpu->xmm, sizeof(fpu->xmm));
}

static void read_fpu_from_xsave(struct kvm_fpu *fpu, const struct xregs_state *record)
{
	memset(fpu, 0, sizeof(*fpu));
	fpu->fcw = 0x37f;
	if (record->header.xfeatures & XFEATURE_MASK_FP) {
		fpu->fcw = record->i387.cwd;
		fpu->fsw = record->i387.swd;
		fpu->ftwx = record->i387.twd;
		fpu->last_opcode = record->i387.fop;
		fpu->last_ip = record->i387.rip;
		fpu->last_dp = record->i387.rdp;
		memcpy(fpu->fpr, record->i387.st_space, sizeof(fpu->fpr));
	}
	if (record->header.xfeatures & XFEATURE_MASK_SSE)
		memcpy(fpu->xmm, record->i387.xmm_space, sizeof(fpu->xmm));
}

static long cpu_xsave(struct pvcpu *cpu, bool write, struct kvm_xsave __user *user)
{
	struct kvm_xsave *state;
	int result;

	if (write) {
		const struct xregs_state *record;
		u64 supported = guest_xsave_mask(cpu);

		state = memdup_user(user, sizeof(*state));
		if (IS_ERR(state))
			return PTR_ERR(state);
		record = (const void *)state;
		if ((record->header.xfeatures & ~supported) || record->header.xcomp_bv ||
		    memchr_inv(record->header.reserved, 0, sizeof(record->header.reserved)) ||
		    (record->i387.mxcsr & 0xffff0000U)) {
			result = -EINVAL;
		} else {
			result = write_stopped_registers(cpu, PVKVM_SET_XSAVE, PVKVM_XSAVE_AT,
							 state, sizeof(*state));
			if (!result && !cpu->ran) {
				read_fpu_from_xsave(&cpu->fpu, record);
				cpu->fpu_set = false;
			}
		}
	} else {
		state = kmalloc(sizeof(*state), GFP_KERNEL);
		if (!state)
			return -ENOMEM;
		result = read_stopped_registers(cpu, PVKVM_GET_XSAVE, PVKVM_XSAVE_AT,
						state, sizeof(*state));
		if (!result && !cpu->ran && cpu->fpu_set)
			apply_fpu_to_xsave((void *)state, &cpu->fpu);
		if (!result && copy_to_user(user, state, sizeof(*state)))
			result = -EFAULT;
	}
	kfree(state);
	return result;
}

static long cpu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pvcpu *cpu = file->private_data;
	struct kvm_fpu fpu;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	void __user *uarg = (void __user *)arg;
	long result;

	if (cpu->vm->owner != current->mm)
		return -EIO;
	/* As in Linux KVM, an ordinary signal does not abandon a run in the lock queue. */
	result = cmd == KVM_RUN ? mutex_lock_killable(&cpu->execution) :
				 mutex_lock_interruptible(&cpu->execution);
	if (result)
		return -EINTR;
	if (cpu->ran && cmd == KVM_SET_SREGS) {
		mutex_unlock(&cpu->execution);
		return -EOPNOTSUPP;
	}
	switch (cmd) {
	case KVM_GET_REGS:
		regs = cpu->regs;
		if (cpu->ran) {
			result = read_stopped_registers(cpu, PVKVM_GET_REGS, PVKVM_REGISTERS_AT, &regs, sizeof(regs));
			if (result)
				break;
		}
		result = copy_to_user(uarg, &regs, sizeof(regs)) ? -EFAULT : 0;
		break;
	case KVM_SET_REGS:
		if (copy_from_user(&regs, uarg, sizeof(regs))) {
			result = -EFAULT;
			break;
		}
		if ((cpu->ran && !registers_fit_mode(&regs, &cpu->sregs)) ||
		    (regs.rflags & ~PVKVM_REAL_MODE_FLAGS) || !(regs.rflags & X86_EFLAGS_FIXED) ||
		    (cpu->ran && !(cpu->sregs.cr0 & X86_CR0_PE) && regs.rip > U16_MAX)) {
			result = -EINVAL;
			break;
		}
		if (cpu->ran) {
			result = write_stopped_registers(cpu, PVKVM_SET_REGS, PVKVM_REGISTERS_AT, &regs, sizeof(regs));
			if (result)
				break;
		}
		cpu->regs = regs;
		result = 0;
		break;
	case KVM_GET_SREGS:
		sregs = cpu->sregs;
		if (cpu->ran) {
			result = read_stopped_registers(cpu, PVKVM_GET_SREGS, PVKVM_REGISTERS_AT, &sregs, sizeof(sregs));
			if (result)
				break;
		} else if (!cpu->sregs_set) {
			result = read_reset_sregs(cpu);
			if (result)
				break;
			sregs = cpu->sregs_reset;
		}
		result = copy_to_user(uarg, &sregs, sizeof(sregs)) ? -EFAULT : 0;
		break;
	case KVM_SET_SREGS:
		if (copy_from_user(&sregs, uarg, sizeof(sregs))) {
			result = -EFAULT;
			break;
		}
		result = read_reset_sregs(cpu);
		if (result)
			break;
		if (!valid_real_entry(&sregs, &cpu->sregs_reset) &&
		    !valid_protected_entry(&sregs, &cpu->sregs_reset) &&
		    !valid_real_entry(&sregs, &reset_sregs) &&
		    !valid_protected_entry(&sregs, &reset_sregs)) {
			result = -EINVAL;
			break;
		}
		cpu->sregs = sregs;
		cpu->sregs_set = true;
		result = 0;
		break;
	case KVM_GET_FPU:
		fpu = cpu->fpu;
		if (cpu->ran) {
			result = read_stopped_registers(cpu, PVKVM_GET_FPU, PVKVM_FPU_AT, &fpu, sizeof(fpu));
			if (result)
				break;
		}
		result = copy_to_user(uarg, &fpu, sizeof(fpu)) ? -EFAULT : 0;
		break;
	case KVM_SET_FPU:
		if (copy_from_user(&fpu, uarg, sizeof(fpu))) {
			result = -EFAULT;
			break;
		}
		/* Linux KVM_FPU preserves the worker's MXCSR. XSAVE includes it. */
		fpu.mxcsr = 0;
		fpu.pad1 = 0;
		fpu.pad2 = 0;
		if (cpu->ran) {
			result = write_stopped_registers(cpu, PVKVM_SET_FPU, PVKVM_FPU_AT, &fpu, sizeof(fpu));
			if (result)
				break;
		}
		cpu->fpu = fpu;
		cpu->fpu_set = true;
		result = 0;
		break;
	case KVM_GET_MSRS:
	case KVM_SET_MSRS:
		result = cpu_msrs(cpu, cmd == KVM_SET_MSRS, uarg);
		break;
	case KVM_GET_CPUID2:
	case KVM_SET_CPUID2:
		result = cpu_cpuid(cpu, cmd == KVM_SET_CPUID2, uarg);
		break;
	case KVM_GET_LAPIC:
	case KVM_SET_LAPIC:
		result = cpu_lapic(cpu, cmd == KVM_SET_LAPIC, uarg);
		break;
	case KVM_GET_DEBUGREGS:
	case KVM_SET_DEBUGREGS:
		result = cpu_debugregs(cpu, cmd == KVM_SET_DEBUGREGS, uarg);
		break;
	case KVM_GET_MP_STATE:
	case KVM_SET_MP_STATE:
		result = cpu_mp_state(cpu, cmd == KVM_SET_MP_STATE, uarg);
		break;
	case KVM_GET_XCRS:
	case KVM_SET_XCRS:
		result = cpu_xcrs(cpu, cmd == KVM_SET_XCRS, uarg);
		break;
	case KVM_GET_XSAVE:
	case KVM_SET_XSAVE:
		result = cpu_xsave(cpu, cmd == KVM_SET_XSAVE, uarg);
		break;
	case KVM_RUN:
		if (arg || cpu->sregs.cs.base || !registers_fit_mode(&cpu->regs, &cpu->sregs) ||
		    (!(cpu->sregs.cr0 & X86_CR0_PE) && cpu->regs.rip > U16_MAX)) {
			result = -EINVAL;
			break;
		}
		result = run_cpu(cpu);
		break;
	default:
		result = -ENOTTY;
	}
	mutex_unlock(&cpu->execution);
	return result;
}

static const struct file_operations cpu_fops = {
	.owner = THIS_MODULE,
	.release = cpu_release,
	.unlocked_ioctl = cpu_ioctl,
	.mmap = cpu_mmap,
};

static int new_cpu(struct pvvm *vm, unsigned long id)
{
	struct pvkvm *p = vm->provider;
	struct pvcpu *cpu;
	int fd;

	if (id >= PVKVM_MAX_CPUS)
		return -EINVAL;
	cpu = kzalloc(sizeof(*cpu), GFP_KERNEL);
	if (!cpu)
		return -ENOMEM;
	cpu->page = vmalloc_user(sizeof(*cpu->page));
	if (!cpu->page) {
		kfree(cpu);
		return -ENOMEM;
	}
	cpu->vm = vm;
	cpu->id = id;
	cpu->regs.rip = 0xfff0;
	cpu->regs.rflags = 2;
	cpu->sregs = reset_sregs;
	cpu->fpu.fcw = 0x37f;
	mutex_init(&cpu->execution);
	mutex_lock(&p->lock);
	if (vm->created_cpus & BIT(id))
		fd = -EEXIST;
	else if (vm->topology_frozen)
		fd = -EBUSY;
	else
		fd = request_for_cpu(cpu, PVKVM_CREATE_VCPU, NULL, NULL);
	if (!fd) {
		fd = anon_inode_getfd("flexvm-vcpu", &cpu_fops, cpu, O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			if (request_for_cpu(cpu, PVKVM_CLOSE_VCPU, NULL, NULL))
				p->dead = true;
		} else {
			vm->created_cpus |= BIT(id);
			vm->open_cpus |= BIT(id);
			kref_get(&vm->refs);
		}
	}
	mutex_unlock(&p->lock);
	if (fd < 0) {
		vfree(cpu->page);
		kfree(cpu);
	}
	return fd;
}

static long device_capability(unsigned long capability)
{
	switch (capability) {
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_CHECK_EXTENSION_VM:
	case KVM_CAP_IMMEDIATE_EXIT:
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_IOEVENTFD_NO_LENGTH:
	case KVM_CAP_IOEVENTFD_ANY_LENGTH:
	case KVM_CAP_PIT:
	case KVM_CAP_PIT2:
	case KVM_CAP_PIT_STATE2:
	case KVM_CAP_IRQFD:
	case KVM_CAP_SET_TSS_ADDR:
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_DEBUGREGS:
	case KVM_CAP_MP_STATE:
	case KVM_CAP_XCRS:
	case KVM_CAP_XSAVE:
	case KVM_CAP_EXT_CPUID:
		return 1;
	case KVM_CAP_NR_MEMSLOTS:
		return PVKVM_MAX_SLOTS;
	case KVM_CAP_NR_VCPUS:
	case KVM_CAP_MAX_VCPUS:
		return PVKVM_MAX_CPUS;
	default:
		return 0;
	}
}

static bool overlaps(u64 base, u64 length, u64 other, u64 other_length)
{
	return base < other + other_length && other < base + length;
}

static int install_slot(struct pvvm *vm, unsigned int id, u64 gpa,
			struct page **pages, unsigned int count)
{
	u64 bytes = count * PAGE_SIZE;
	unsigned int other;

	if (vm->provider->dead)
		return -ENODEV;
	if (vm->slots_exposed)
		return -EBUSY;
	if (vm->slots[id].count)
		return -EEXIST;
	if (count > PVKVM_MAX_PAGES - vm->total_pages)
		return -ENOSPC;
	if (vm->tss_set && overlaps(gpa, bytes, vm->tss_gpa, PVKVM_TSS_SIZE))
		return -EEXIST;
	for (other = 0; other < PVKVM_MAX_SLOTS; other++) {
		const struct pvslot *existing = &vm->slots[other];

		if (existing->count && overlaps(gpa, bytes, existing->gpa, existing->count * PAGE_SIZE))
			return -EEXIST;
	}
	vm->slots[id] = (struct pvslot){ .pages = pages, .gpa = gpa, .count = count };
	vm->total_pages += count;
	return 0;
}

static long vm_ioeventfd(struct pvvm *vm, struct kvm_ioeventfd __user *user)
{
	const u32 allowed = KVM_IOEVENTFD_FLAG_DATAMATCH | KVM_IOEVENTFD_FLAG_PIO |
			    KVM_IOEVENTFD_FLAG_DEASSIGN;
	struct kvm_ioeventfd argument;
	struct eventfd_ctx *eventfd;
	struct pv_ioeventfd *entry, *new = NULL;
	bool remove, pio, datamatch;
	long result;

	if (copy_from_user(&argument, user, sizeof(argument)))
		return -EFAULT;
	remove = argument.flags & KVM_IOEVENTFD_FLAG_DEASSIGN;
	pio = argument.flags & KVM_IOEVENTFD_FLAG_PIO;
	datamatch = argument.flags & KVM_IOEVENTFD_FLAG_DATAMATCH;
	if (argument.flags & ~allowed ||
	    (argument.len && (!is_power_of_2(argument.len) || argument.len > sizeof(u64))) ||
	    (!argument.len && datamatch) || argument.addr + argument.len < argument.addr)
		return -EINVAL;
	eventfd = eventfd_ctx_fdget(argument.fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);
	if (!remove) {
		new = kzalloc(sizeof(*new), GFP_KERNEL_ACCOUNT);
		if (!new) {
			result = -ENOMEM;
			goto out;
		}
		new->eventfd = eventfd;
		new->address = argument.addr;
		new->data = argument.datamatch;
		new->length = argument.len;
		new->pio = pio;
		new->datamatch = datamatch;
	}
	result = mutex_lock_interruptible(&vm->ioevent_lock);
	if (result)
		goto out;
	list_for_each_entry(entry, &vm->ioevents, node) {
		if (entry->address != argument.addr || entry->pio != pio)
			continue;
		if (remove) {
			if (entry->eventfd != eventfd || entry->length != argument.len ||
			    entry->datamatch != datamatch ||
			    (datamatch && entry->data != argument.datamatch))
				continue;
			list_del(&entry->node);
			release_ioeventfd(entry);
			goto unlock;
		}
		if (!entry->length || !argument.len ||
		    (entry->length == argument.len &&
		     (!entry->datamatch || !datamatch || entry->data == argument.datamatch))) {
			result = -EEXIST;
			goto unlock;
		}
	}
	if (remove) {
		result = -ENOENT;
	} else {
		list_add_tail(&new->node, &vm->ioevents);
		mutex_unlock(&vm->ioevent_lock);
		return 0;
	}
unlock:
	mutex_unlock(&vm->ioevent_lock);
out:
	eventfd_ctx_put(eventfd);
	kfree(new);
	return result;
}

static long configure_irqfd(struct pvvm *vm, struct kvm_irqfd __user *user)
{
	struct kvm_irqfd argument;
	struct pv_irqfd *entry, *next, *new = NULL;
	struct eventfd_ctx *eventfd;
	struct file *file;
	bool remove;
	int result = 0;

	if (copy_from_user(&argument, user, sizeof(argument)))
		return -EFAULT;
	if (argument.flags & ~KVM_IRQFD_FLAG_DEASSIGN || argument.gsi >= PVKVM_GSI_COUNT)
		return -EINVAL;
	remove = argument.flags & KVM_IRQFD_FLAG_DEASSIGN;
	if (!remove && !READ_ONCE(vm->irqchip_created))
		return -EAGAIN;
	file = eventfd_fget(argument.fd);
	if (IS_ERR(file))
		return PTR_ERR(file);
	eventfd = eventfd_ctx_fileget(file);
	if (IS_ERR(eventfd)) {
		result = PTR_ERR(eventfd);
		goto put_file;
	}
	if (!remove) {
		new = kzalloc(sizeof(*new), GFP_KERNEL);
		if (!new) {
			result = -ENOMEM;
			goto put_event;
		}
		new->vm = vm;
		new->eventfd = eventfd;
		new->gsi = argument.gsi;
		init_waitqueue_func_entry(&new->wait, wake_irqfd);
		init_poll_funcptr(&new->poll, queue_irqfd);
	}
	mutex_lock(&vm->irqfd_lock);
	list_for_each_entry_safe(entry, next, &vm->irqfds, node) {
		if (entry->eventfd != eventfd)
			continue;
		if (!remove)
			result = -EBUSY;
		else if (entry->gsi == argument.gsi)
			release_irqfd(entry);
		break;
	}
	if (new && !result) {
		unsigned long flags;

		list_add_tail(&new->node, &vm->irqfds);
		vfs_poll(file, &new->poll);
		/* Claim pending data under the same lock as the wake callback. */
		spin_lock_irqsave(&new->head->lock, flags);
		signal_irqfd(new);
		spin_unlock_irqrestore(&new->head->lock, flags);
		mutex_unlock(&vm->irqfd_lock);
		goto put_file;
	}
	mutex_unlock(&vm->irqfd_lock);
	kfree(new);
put_event:
	eventfd_ctx_put(eventfd);
put_file:
	fput(file);
	return result;
}

static long create_irqchip(struct pvvm *vm, unsigned long arg)
{
	struct pvkvm *p = vm->provider;
	int result;

	if (arg)
		return -EINVAL;
	result = mutex_lock_interruptible(&p->lock);
	if (result)
		return result;
	if (vm->irqchip_created)
		result = -EEXIST;
	else if (vm->created_cpus)
		result = -EINVAL;
	else {
		result = request(p, PVKVM_CREATE_IRQCHIP, NULL, NULL);
		if (!result)
			WRITE_ONCE(vm->irqchip_created, true);
	}
	mutex_unlock(&p->lock);
	return result;
}

static long access_irqchip(struct pvvm *vm, bool write, struct kvm_irqchip __user *user)
{
	struct pvkvm *p = vm->provider;
	struct kvm_irqchip *chip;
	int result;

	chip = memdup_user(user, sizeof(*chip));
	if (IS_ERR(chip))
		return PTR_ERR(chip);
	if (chip->chip_id >= KVM_NR_IRQCHIPS) {
		result = -EINVAL;
		goto free_chip;
	}
	if (write && chip->chip_id == KVM_IRQCHIP_IOAPIC &&
	    (chip->chip.ioapic.base_address != PVKVM_IOAPIC_GPA ||
	     chip->chip.ioapic.ioregsel > U8_MAX || chip->chip.ioapic.id > U8_MAX ||
	     chip->chip.ioapic.irr >= BIT(PVKVM_GSI_COUNT) || chip->chip.ioapic.pad)) {
		result = -EINVAL;
		goto free_chip;
	}
	result = mutex_lock_interruptible(&p->lock);
	if (result)
		goto free_chip;
	if (!vm->irqchip_created) {
		result = -ENXIO;
	} else if (p->dead) {
		result = -ENODEV;
	} else {
		memcpy_toio(p->mailbox + PVKVM_IRQCHIP_AT, chip, sizeof(*chip));
		result = request(p, write ? PVKVM_SET_IRQCHIP : PVKVM_GET_IRQCHIP, NULL, NULL);
		if (!result && !write)
			memcpy_fromio(chip, p->mailbox + PVKVM_IRQCHIP_AT, sizeof(*chip));
	}
	mutex_unlock(&p->lock);
	if (!result && !write && copy_to_user(user, chip, sizeof(*chip)))
		result = -EFAULT;
free_chip:
	kfree(chip);
	return result;
}

static long set_irq_line(struct pvvm *vm, struct kvm_irq_level __user *user)
{
	struct pvkvm *p = vm->provider;
	struct kvm_irq_level irq;
	int result;

	if (copy_from_user(&irq, user, sizeof(irq)))
		return -EFAULT;
	if (irq.irq >= PVKVM_GSI_COUNT || irq.level > 1)
		return -EINVAL;
	result = mutex_lock_interruptible(&p->lock);
	if (result)
		return result;
	if (!vm->irqchip_created) {
		result = -ENXIO;
	} else if (p->dead) {
		result = -ENODEV;
	} else {
		memcpy_toio(p->mailbox + PVKVM_IRQ_AT, &irq, sizeof(irq));
		result = request(p, PVKVM_SET_IRQ_LINE, NULL, NULL);
	}
	mutex_unlock(&p->lock);
	return result;
}

static long create_pit(struct pvvm *vm, struct kvm_pit_config __user *user)
{
	struct pvkvm *p = vm->provider;
	struct kvm_pit_config config = { .flags = KVM_PIT_SPEAKER_DUMMY };
	int result;

	if (user && copy_from_user(&config, user, sizeof(config)))
		return -EFAULT;
	if (config.flags & ~KVM_PIT_SPEAKER_DUMMY)
		return -EINVAL;
	result = mutex_lock_interruptible(&p->lock);
	if (result)
		return result;
	if (vm->pit_created) {
		result = -EEXIST;
	} else if (!vm->irqchip_created) {
		result = -ENXIO;
	} else if (vm->topology_frozen) {
		result = -EBUSY;
	} else if (p->dead) {
		result = -ENODEV;
	} else {
		writel(config.flags, p->mailbox + PVKVM_PIT_FLAGS_AT);
		result = request(p, PVKVM_CREATE_PIT, NULL, NULL);
		if (!result)
			vm->pit_created = true;
	}
	mutex_unlock(&p->lock);
	return result;
}

static long access_pit_state(struct pvvm *vm, bool write, struct kvm_pit_state2 __user *user)
{
	struct pvkvm *p = vm->provider;
	struct kvm_pit_state2 state;
	unsigned int i;
	int result;

	if (write && copy_from_user(&state, user, sizeof(state)))
		return -EFAULT;
	if (write) {
		if (state.flags & ~(KVM_PIT_FLAGS_HPET_LEGACY | KVM_PIT_FLAGS_SPEAKER_DATA_ON))
			return -EINVAL;
		for (i = 0; i < ARRAY_SIZE(state.channels); i++) {
			const struct kvm_pit_channel_state *ch = &state.channels[i];

			if (ch->count > 65536 || ch->count_latched > 3 || ch->status_latched > 1 ||
			    ch->read_state > 4 || ch->write_state > 4 || ch->rw_mode > 3 ||
			    (ch->mode > 7 && ch->mode != 0xff) || ch->bcd > 1 || ch->gate > 1)
				return -EINVAL;
		}
	}
	result = mutex_lock_interruptible(&p->lock);
	if (result)
		return result;
	if (!vm->pit_created) {
		result = -ENXIO;
	} else if (p->dead) {
		result = -ENODEV;
	} else {
		if (write)
			memcpy_toio(p->mailbox + PVKVM_PIT_STATE_AT, &state, sizeof(state));
		result = request(p, write ? PVKVM_SET_PIT : PVKVM_GET_PIT, NULL, NULL);
		if (!result && !write)
			memcpy_fromio(&state, p->mailbox + PVKVM_PIT_STATE_AT, sizeof(state));
	}
	mutex_unlock(&p->lock);
	if (!result && !write && copy_to_user(user, &state, sizeof(state)))
		return -EFAULT;
	return result;
}

static bool valid_tss_address(unsigned long gpa)
{
	if (!PAGE_ALIGNED(gpa) || gpa > (1ULL << 32) - PVKVM_TSS_SIZE)
		return false;
	/* Leave the legacy ROM, MMIO exit device, APICs, and reset ROM in place. */
	return !overlaps(gpa, PVKVM_TSS_SIZE, 0xa0000, 0x60000) &&
	       !overlaps(gpa, PVKVM_TSS_SIZE, 0xd0000000, PAGE_SIZE) &&
	       !overlaps(gpa, PVKVM_TSS_SIZE, 0xfec00000, 0x400000) &&
	       !overlaps(gpa, PVKVM_TSS_SIZE, 0xffff0000, 0x10000);
}

static long set_tss_address(struct pvvm *vm, unsigned long gpa)
{
	struct pvkvm *p = vm->provider;
	unsigned int id;
	int result;

	if (!valid_tss_address(gpa))
		return -EINVAL;
	result = mutex_lock_interruptible(&p->lock);
	if (result)
		return result;
	if (p->dead) {
		result = -ENODEV;
		goto out;
	}
	if (vm->topology_frozen) {
		result = -EBUSY;
		goto out;
	}
	for (id = 0; id < PVKVM_MAX_SLOTS; id++) {
		const struct pvslot *slot = &vm->slots[id];

		if (slot->count && overlaps(gpa, PVKVM_TSS_SIZE, slot->gpa, slot->count * PAGE_SIZE)) {
			result = -EEXIST;
			goto out;
		}
	}
	writel(gpa, p->mailbox + PVKVM_TSS_AT);
	result = request(p, PVKVM_SET_TSS_ADDR, NULL, NULL);
	if (!result) {
		vm->tss_gpa = gpa;
		vm->tss_set = true;
	}
out:
	mutex_unlock(&p->lock);
	return result;
}

static long vm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pvvm *vm = file->private_data;
	struct pvkvm *p = vm->provider;
	struct kvm_userspace_memory_region memory;
	struct page **slot;
	unsigned int pages;
	long pinned;
	int result;

	if (vm->owner != current->mm)
		return -EIO;
	if (cmd == KVM_CREATE_VCPU)
		return new_cpu(vm, arg);
	if (cmd == KVM_CHECK_EXTENSION)
		return device_capability(arg);
	if (cmd == KVM_IOEVENTFD)
		return vm_ioeventfd(vm, (void __user *)arg);
	if (cmd == KVM_CREATE_IRQCHIP)
		return create_irqchip(vm, arg);
	if (cmd == KVM_GET_IRQCHIP || cmd == KVM_SET_IRQCHIP)
		return access_irqchip(vm, cmd == KVM_SET_IRQCHIP, (void __user *)arg);
	if (cmd == KVM_IRQ_LINE)
		return set_irq_line(vm, (void __user *)arg);
	if (cmd == KVM_IRQFD)
		return configure_irqfd(vm, (void __user *)arg);
	if (cmd == KVM_CREATE_PIT)
		return create_pit(vm, NULL);
	if (cmd == KVM_CREATE_PIT2)
		return arg ? create_pit(vm, (void __user *)arg) : -EFAULT;
	if (cmd == KVM_GET_PIT2 || cmd == KVM_SET_PIT2)
		return access_pit_state(vm, cmd == KVM_SET_PIT2, (void __user *)arg);
	if (cmd == KVM_SET_TSS_ADDR)
		return set_tss_address(vm, arg);
	if (cmd != KVM_SET_USER_MEMORY_REGION)
		return -ENOTTY;
	if (copy_from_user(&memory, (void __user *)arg, sizeof(memory)))
		return -EFAULT;
	if (memory.slot >= PVKVM_MAX_SLOTS || memory.flags ||
	    memory.guest_phys_addr >= PVKVM_PC_HIGH_RAM_LIMIT || !PAGE_ALIGNED(memory.guest_phys_addr) ||
	    !memory.memory_size || memory.memory_size > PVKVM_MAX_PAGES * PAGE_SIZE ||
	    memory.guest_phys_addr + memory.memory_size > PVKVM_PC_HIGH_RAM_LIMIT ||
	    !PAGE_ALIGNED(memory.memory_size) || !memory.userspace_addr ||
	    !PAGE_ALIGNED(memory.userspace_addr))
		return -EINVAL;
	pages = memory.memory_size / PAGE_SIZE;
	slot = kvmalloc_array(pages, sizeof(*slot), GFP_KERNEL);
	if (!slot)
		return -ENOMEM;
	pinned = pin_user_pages_fast(memory.userspace_addr, pages, FOLL_WRITE | FOLL_LONGTERM, slot);
	if (pinned != pages) {
		if (pinned > 0)
			unpin_user_pages(slot, pinned);
		kvfree(slot);
		return pinned < 0 ? pinned : -EFAULT;
	}
	mutex_lock(&p->lock);
	result = install_slot(vm, memory.slot, memory.guest_phys_addr, slot, pages);
	mutex_unlock(&p->lock);
	if (result) {
		unpin_user_pages(slot, pages);
		kvfree(slot);
	}
	return result;
}

static const struct file_operations vm_fops = {
	.owner = THIS_MODULE,
	.release = vm_release,
	.unlocked_ioctl = vm_ioctl,
};

static int new_vm(struct pvkvm *p, unsigned long type)
{
	struct pvvm *vm;
	int fd;

	if (type)
		return -EINVAL;
	vm = kzalloc(sizeof(*vm), GFP_KERNEL);
	if (!vm)
		return -ENOMEM;
	vm->provider = p;
	vm->owner = current->mm;
	mutex_init(&vm->ioevent_lock);
	INIT_LIST_HEAD(&vm->ioevents);
	mutex_init(&vm->irqfd_lock);
	INIT_LIST_HEAD(&vm->irqfds);
	INIT_WORK(&vm->irqfd_reap, reap_irqfds);
	mmgrab(vm->owner);
	kref_init(&vm->refs);
	mutex_lock(&p->lock);
	fd = p->vm_open ? -EBUSY : request(p, PVKVM_CREATE_VM, 0, NULL);
	if (!fd) {
		fd = anon_inode_getfd("flexvm-vm", &vm_fops, vm, O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			close_object(p, PVKVM_CLOSE_VM);
		} else {
			p->vm_open = true;
			kref_get(&p->refs);
		}
	}
	mutex_unlock(&p->lock);
	if (fd < 0) {
		mmdrop(vm->owner);
		kfree(vm);
	}
	return fd;
}

/* misc_open installs the registered miscdevice before replacing the fops. */
static int device_open(struct inode *inode, struct file *file)
{
	struct pvkvm *p = container_of(file->private_data, struct pvkvm, misc);

	kref_get(&p->refs);
	file->private_data = p;
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	struct pvkvm *p = file->private_data;

	kref_put(&p->refs, provider_free);
	return 0;
}

static long supported_cpuid(struct pvkvm *p, struct kvm_cpuid2 __user *user)
{
	struct pvkvm_cpuid_table *table;
	u32 capacity;
	long result;

	if (get_user(capacity, &user->nent))
		return -EFAULT;
	if (!capacity)
		return -E2BIG;
	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return -ENOMEM;
	result = mutex_lock_interruptible(&p->lock);
	if (result)
		goto out;
	result = request(p, PVKVM_GET_SUPPORTED_CPUID, NULL, NULL);
	if (!result) {
		memcpy_fromio(table, p->mailbox + PVKVM_CPUID_AT, sizeof(*table));
		if (!table->count || table->count > PVKVM_CPUID_MAX || table->reserved || !valid_cpuid_table(table)) {
			p->dead = true;
			result = -EIO;
		}
	}
	mutex_unlock(&p->lock);
	if (!result)
		result = copy_cpuid(user, table, capacity);
out:
	kfree(table);
	return result;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case KVM_GET_API_VERSION:
		return KVM_API_VERSION;
	case KVM_GET_VCPU_MMAP_SIZE:
		return sizeof(struct run_page);
	case KVM_CHECK_EXTENSION:
		return device_capability(arg);
	case KVM_GET_MSR_INDEX_LIST: {
		struct kvm_msr_list __user *list = (void __user *)arg;
		u32 capacity;

		if (get_user(capacity, &list->nmsrs) || put_user(ARRAY_SIZE(boot_msr_indices), &list->nmsrs))
			return -EFAULT;
		if (capacity < ARRAY_SIZE(boot_msr_indices))
			return -E2BIG;
		return copy_to_user(list->indices, boot_msr_indices, sizeof(boot_msr_indices)) ? -EFAULT : 0;
	}
	case KVM_GET_SUPPORTED_CPUID:
		return supported_cpuid(file->private_data, (void __user *)arg);
	case KVM_CREATE_VM:
		return new_vm(file->private_data, arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations device_fops = {
	.owner = THIS_MODULE,
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl,
};

static irqreturn_t reply_ready(int irq, void *data)
{
	struct pvkvm *p = data;

	atomic_inc(&p->interrupt_count);
	wake_up(&p->replied);
	return IRQ_HANDLED;
}

static int pvkvm_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	struct pvkvm *p;
	int result;

	BUILD_BUG_ON(sizeof(struct run_page) != 2 * PAGE_SIZE);
	BUILD_BUG_ON(PAGE_SIZE != PVKVM_GUEST_PAGE_SIZE);
	BUILD_BUG_ON(PVKVM_SLOT_TABLE_AT + PVKVM_MAX_SLOTS * PVKVM_SLOT_RECORD_SIZE > PVKVM_FPU_AT);
	BUILD_BUG_ON(sizeof(struct kvm_fpu) != PVKVM_FPU_BYTES);
	BUILD_BUG_ON(PVKVM_FPU_AT + PVKVM_FPU_BYTES > PVKVM_RAM_ADDRESS_AT);
	BUILD_BUG_ON(PVKVM_RAM_ADDRESS_AT + PVKVM_MAX_PAGES * sizeof(u64) > PVKVM_MSR_AT);
	BUILD_BUG_ON(PVKVM_MSR_AT + sizeof(struct pvkvm_msr_batch) > PVKVM_CPUID_AT);
	BUILD_BUG_ON(PVKVM_CPUID_AT + sizeof(struct pvkvm_cpuid_table) > PVKVM_EXIT_AT);
	BUILD_BUG_ON(PVKVM_EXIT_AT + sizeof(struct pvkvm_run_exit) > PVKVM_COMPLETION_AT);
	BUILD_BUG_ON(PVKVM_COMPLETION_AT + sizeof(struct pvkvm_read_completion) > PVKVM_IRQ_AT);
	BUILD_BUG_ON(PVKVM_IRQ_AT + sizeof(struct kvm_irq_level) > PVKVM_PIT_FLAGS_AT);
	BUILD_BUG_ON(PVKVM_PIT_FLAGS_AT + sizeof(u32) > PVKVM_TSS_AT);
	BUILD_BUG_ON(PVKVM_TSS_AT + sizeof(u32) > PVKVM_LAPIC_AT);
	BUILD_BUG_ON(sizeof(struct kvm_lapic_state) != PVKVM_LAPIC_BYTES);
	BUILD_BUG_ON(PVKVM_LAPIC_VALID_AT + sizeof(u32) > PVKVM_REGISTERS_AT);
	BUILD_BUG_ON(PVKVM_LAPIC_AT + PVKVM_LAPIC_BYTES > PVKVM_PIO_DATA_AT);
	BUILD_BUG_ON(PVKVM_PIO_DATA_AT + PVKVM_PIO_BYTES > PVKVM_IRQCHIP_AT);
	BUILD_BUG_ON(sizeof(struct kvm_irqchip) != PVKVM_IRQCHIP_BYTES);
	BUILD_BUG_ON(PVKVM_IRQCHIP_AT + PVKVM_IRQCHIP_BYTES > PVKVM_PIT_STATE_AT);
	BUILD_BUG_ON(sizeof(struct kvm_pit_state2) != PVKVM_PIT_STATE_BYTES);
	BUILD_BUG_ON(PVKVM_PIT_STATE_AT + PVKVM_PIT_STATE_BYTES > PVKVM_DEBUGREGS_AT);
	BUILD_BUG_ON(sizeof(struct kvm_debugregs) != PVKVM_DEBUGREGS_BYTES);
	BUILD_BUG_ON(PVKVM_DEBUGREGS_AT + PVKVM_DEBUGREGS_BYTES > PVKVM_MP_STATE_AT);
	BUILD_BUG_ON(sizeof(struct kvm_mp_state) != sizeof(u32));
	BUILD_BUG_ON(PVKVM_MP_STATE_AT + sizeof(struct kvm_mp_state) > PVKVM_XCRS_AT);
	BUILD_BUG_ON(sizeof(struct kvm_xcrs) != PVKVM_XCRS_BYTES);
	BUILD_BUG_ON(PVKVM_XCRS_AT + PVKVM_XCRS_BYTES > PVKVM_XSAVE_AT);
	BUILD_BUG_ON(sizeof(struct kvm_xsave) != PVKVM_XSAVE_BYTES);
	if (pci_resource_len(dev, 0) < PVKVM_DOORBELL_AT + sizeof(u32) ||
	    pci_resource_len(dev, 2) < PVKVM_XSAVE_AT + PVKVM_XSAVE_BYTES)
		return -ENODEV;
	result = pcim_enable_device(dev);
	if (result)
		return result;
	pci_set_master(dev);
	result = pcim_iomap_regions(dev, BIT(0) | BIT(2), KBUILD_MODNAME);
	if (result)
		return result;
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	kref_init(&p->refs);
	mutex_init(&p->lock);
	init_waitqueue_head(&p->replied);
	atomic_set(&p->interrupt_count, 0);
	p->doorbell = pcim_iomap_table(dev)[0];
	p->mailbox = pcim_iomap_table(dev)[2];
	spin_lock_init(&p->irqfd_doorbell_lock);
	p->irqfd_doorbell_live = true;
	if (readl(p->doorbell + PVKVM_IVPOSITION_AT) != PVKVM_GUEST_POSITION ||
	    readl(p->mailbox + PVKVM_MAGIC_AT) != PVKVM_MAGIC ||
	    readl(p->mailbox + PVKVM_VERSION_AT) != PVKVM_VERSION ||
	    readl(p->mailbox + PVKVM_REQUEST_AT) || readl(p->mailbox + PVKVM_REPLY_AT)) {
		result = -ENODEV;
		goto free_provider;
	}
	result = pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_MSIX);
	if (result < 0)
		goto free_provider;
	p->irq = pci_irq_vector(dev, 0);
	result = request_irq(p->irq, reply_ready, 0, KBUILD_MODNAME, p);
	if (result)
		goto free_vectors;
	p->misc.minor = 232;
	p->misc.name = "kvm";
	p->misc.fops = &device_fops;
	p->misc.mode = 0600;
	result = misc_register(&p->misc);
	if (result)
		goto release_irq;
	pci_set_drvdata(dev, p);
	return 0;

release_irq:
	free_irq(p->irq, p);
free_vectors:
	pci_free_irq_vectors(dev);
free_provider:
	kfree(p);
	return result;
}

static void pvkvm_remove(struct pci_dev *dev)
{
	struct pvkvm *p = pci_get_drvdata(dev);
	unsigned long flags;

	misc_deregister(&p->misc);
	spin_lock_irqsave(&p->irqfd_doorbell_lock, flags);
	p->irqfd_doorbell_live = false;
	spin_unlock_irqrestore(&p->irqfd_doorbell_lock, flags);
	mutex_lock(&p->lock);
	p->dead = true;
	p->mailbox = NULL;
	mutex_unlock(&p->lock);
	free_irq(p->irq, p);
	pci_free_irq_vectors(dev);
	kref_put(&p->refs, provider_free);
}

/* Standard ivshmem PCI device. The magic protects unrelated shared segments. */
static const struct pci_device_id pvkvm_ids[] = {
	{ PCI_DEVICE(0x1af4, 0x1110) },
	{},
};

static struct pci_driver pvkvm_driver = {
	.name = KBUILD_MODNAME,
	.id_table = pvkvm_ids,
	.probe = pvkvm_probe,
	.remove = pvkvm_remove,
};
module_pci_driver(pvkvm_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FlexVM parent-managed KVM run prototype");
