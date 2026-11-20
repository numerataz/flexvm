// SPDX-License-Identifier: GPL-2.0-only
/*
 * Experimental x86 proof for a KVM client and a parent CPU worker.
 * One VM, pinned RAM slots, serialized vCPUs, and port-output exits.
 */
#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kref.h>
#include <linux/kvm.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <asm/msr-index.h>
#include <asm/processor-flags.h>
#include "mailbox.h"

#define PVKVM_REAL_MODE_FLAGS (X86_EFLAGS_FIXED | X86_EFLAGS_CF | X86_EFLAGS_PF | \
			       X86_EFLAGS_AF | X86_EFLAGS_ZF | X86_EFLAGS_SF | \
			       X86_EFLAGS_DF | X86_EFLAGS_OF)

struct pvkvm {
	struct kref refs;
	struct mutex lock;
	struct miscdevice misc;
	void __iomem *mailbox;
	void __iomem *doorbell;
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

struct pvvm {
	struct kref refs;
	struct pvkvm *provider;
	struct mm_struct *owner;
	struct pvslot slots[PVKVM_MAX_SLOTS];
	unsigned int total_pages;
	bool slots_exposed;
	bool topology_frozen;
	unsigned long created_cpus;
	unsigned long open_cpus;
};

struct run_page {
	struct kvm_run run;
	u8 data;
};

struct pvcpu {
	struct pvvm *vm;
	struct mutex execution;
	struct run_page *page;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_fpu fpu;
	unsigned int id;
	bool ran;
	bool fpu_set;
};

static const struct kvm_sregs reset_sregs = {
	.cs = { .base = 0xffff0000, .limit = 0xffff, .selector = 0xf000, .present = 1 },
};

static bool long_mode(const struct kvm_sregs *sregs)
{
	return sregs->efer & EFER_LMA;
}

static bool valid_protected_entry(const struct kvm_sregs *sregs)
{
	static const struct kvm_segment code = {
		.limit = U32_MAX, .selector = 8, .type = 11, .present = 1,
		.db = 1, .s = 1, .g = 1,
	};
	static const struct kvm_segment data = {
		.limit = U32_MAX, .selector = 16, .type = 3, .present = 1,
		.db = 1, .s = 1, .g = 1,
	};
	struct kvm_sregs wanted = reset_sregs;

	wanted.cs = code;
	wanted.ds = wanted.es = wanted.fs = wanted.gs = wanted.ss = data;
	wanted.cr0 = X86_CR0_PE;
	wanted.gdt.limit = 23;
	wanted.gdt.base = sregs->gdt.base;
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
		   u8 *io_value)
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
	if (!status && io_value)
		*io_value = readl(m + PVKVM_IO_VALUE_AT);
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
			   const struct pvvm *memory, u8 *output)
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

static void vm_free(struct kref *ref)
{
	struct pvvm *vm = container_of(ref, struct pvvm, refs);
	struct pvkvm *p = vm->provider;
	bool closed;
	unsigned int id;

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
	kfree(cpu);
	return 0;
}

static int cpu_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct pvcpu *cpu = file->private_data;

	if (cpu->vm->owner != current->mm)
		return -EIO;
	if (vma->vm_pgoff || vma->vm_end - vma->vm_start != PAGE_SIZE ||
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

static int run_cpu(struct pvcpu *cpu)
{
	struct pvvm *vm = cpu->vm;
	struct pvkvm *p = vm->provider;
	const struct pvvm *memory;
	int result;

	result = mutex_lock_interruptible(&p->lock);
	if (result)
		return -EINTR;
	if (signal_pending(current)) {
		result = -EINTR;
		goto unlock;
	}
	if (p->dead) {
		result = -ENODEV;
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
	}
	result = request_for_cpu(cpu, PVKVM_RUN, memory, &cpu->page->data);
	if (!result || result == -EINTR)
		cpu->ran = true;
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

static long cpu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pvcpu *cpu = file->private_data;
	struct run_page *page = cpu->page;
	struct kvm_fpu fpu;
	struct kvm_sregs sregs, wanted;
	struct kvm_regs regs;
	void __user *uarg = (void __user *)arg;
	long result;

	if (cpu->vm->owner != current->mm)
		return -EIO;
	result = mutex_lock_interruptible(&cpu->execution);
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
		}
		result = copy_to_user(uarg, &sregs, sizeof(sregs)) ? -EFAULT : 0;
		break;
	case KVM_SET_SREGS:
		if (copy_from_user(&sregs, uarg, sizeof(sregs))) {
			result = -EFAULT;
			break;
		}
		wanted = reset_sregs;
		wanted.cs.base = 0;
		wanted.cs.selector = 0;
		if (memcmp(&sregs, &wanted, sizeof(sregs)) && !valid_protected_entry(&sregs)) {
			result = -EINVAL;
			break;
		}
		cpu->sregs = sregs;
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
	case KVM_RUN:
		if (arg || cpu->sregs.cs.base || !registers_fit_mode(&cpu->regs, &cpu->sregs) ||
		    (!(cpu->sregs.cr0 & X86_CR0_PE) && cpu->regs.rip > U16_MAX)) {
			result = -EINVAL;
			break;
		}
		if (READ_ONCE(page->run.immediate_exit) || signal_pending(current)) {
			result = -EINTR;
			break;
		}
		result = run_cpu(cpu);
		if (result)
			break;
		page->run.io.direction = KVM_EXIT_IO_OUT;
		page->run.io.size = 1;
		page->run.io.port = PVKVM_IO_PORT;
		page->run.io.count = 1;
		page->run.io.data_offset = offsetof(struct run_page, data);
		page->run.exit_reason = KVM_EXIT_IO;
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
	cpu->page = vmalloc_user(PAGE_SIZE);
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

static int install_slot(struct pvvm *vm, unsigned int id, u64 gpa,
			struct page **pages, unsigned int count)
{
	u64 end = gpa + count * PAGE_SIZE;
	unsigned int other;

	if (vm->provider->dead)
		return -ENODEV;
	if (vm->slots_exposed)
		return -EBUSY;
	if (vm->slots[id].count)
		return -EEXIST;
	if (count > PVKVM_MAX_PAGES - vm->total_pages)
		return -ENOSPC;
	for (other = 0; other < PVKVM_MAX_SLOTS; other++) {
		const struct pvslot *existing = &vm->slots[other];

		if (existing->count && gpa < existing->gpa + existing->count * PAGE_SIZE &&
		    existing->gpa < end)
			return -EEXIST;
	}
	vm->slots[id] = (struct pvslot){ .pages = pages, .gpa = gpa, .count = count };
	vm->total_pages += count;
	return 0;
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
	if (cmd != KVM_SET_USER_MEMORY_REGION)
		return -ENOTTY;
	if (copy_from_user(&memory, (void __user *)arg, sizeof(memory)))
		return -EFAULT;
	if (memory.slot >= PVKVM_MAX_SLOTS || memory.flags || memory.guest_phys_addr < PVKVM_GUEST_START ||
	    memory.guest_phys_addr >= PVKVM_PC_HIGH_RAM_LIMIT || !PAGE_ALIGNED(memory.guest_phys_addr) ||
	    !memory.memory_size || memory.memory_size > PVKVM_MAX_PAGES * PAGE_SIZE ||
	    memory.guest_phys_addr + memory.memory_size > PVKVM_PC_HIGH_RAM_LIMIT ||
	    (memory.guest_phys_addr < PVKVM_PC_HIGH_RAM_START &&
	     memory.guest_phys_addr + memory.memory_size > PVKVM_PC_LOW_RAM_LIMIT) ||
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

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case KVM_GET_API_VERSION:
		return KVM_API_VERSION;
	case KVM_GET_VCPU_MMAP_SIZE:
		return PAGE_SIZE;
	case KVM_CHECK_EXTENSION:
		return device_capability(arg);
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

	BUILD_BUG_ON(sizeof(struct run_page) > PAGE_SIZE);
	BUILD_BUG_ON(PAGE_SIZE != PVKVM_GUEST_PAGE_SIZE);
	BUILD_BUG_ON(PVKVM_SLOT_TABLE_AT + PVKVM_MAX_SLOTS * PVKVM_SLOT_RECORD_SIZE > PVKVM_FPU_AT);
	BUILD_BUG_ON(sizeof(struct kvm_fpu) != PVKVM_FPU_BYTES);
	BUILD_BUG_ON(PVKVM_FPU_AT + PVKVM_FPU_BYTES > PVKVM_RAM_ADDRESS_AT);
	if (pci_resource_len(dev, 0) < PVKVM_DOORBELL_AT + sizeof(u32) ||
	    pci_resource_len(dev, 2) < PVKVM_RAM_ADDRESS_AT + PVKVM_MAX_PAGES * sizeof(u64))
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

	misc_deregister(&p->misc);
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
