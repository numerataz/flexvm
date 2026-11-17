// SPDX-License-Identifier: GPL-2.0-only
/*
 * Experimental x86 proof for a KVM client and a parent CPU worker.
 * One VM, one vCPU, one copied real-mode 4 KiB slot, and port-output exits.
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
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include "mailbox.h"

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

struct pvvm {
	struct kref refs;
	struct pvkvm *provider;
	struct mm_struct *owner;
	u64 userspace_addr;
	bool cpu_open;
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
	bool ran;
};

static const struct kvm_regs entry_regs = {
	.rip = PVKVM_GUEST_START,
	.rflags = 2,
};

static const struct kvm_sregs reset_sregs = {
	.cs = { .base = 0xffff0000, .limit = 0xffff, .selector = 0xf000, .present = 1 },
};

/* The device lock serializes mailbox use, including close and PCI teardown. */
static int request(struct pvkvm *provider, enum pvkvm_command command, void *page,
		   u8 *io_value)
{
	void __iomem *m = provider->mailbox;
	u32 before, seq;
	long waited;
	int status, interrupts;

	if (provider->dead)
		return -ENODEV;
	before = readl(m + PVKVM_REQUEST_AT);
	if (readl(m + PVKVM_REPLY_AT) != before) {
		provider->dead = true;
		return -EIO;
	}
	seq = before + 1;
	interrupts = atomic_read(&provider->interrupt_count);
	if (page)
		memcpy_toio(m + PVKVM_MEMORY_AT, page, PVKVM_MEMORY_LEN);
	writel(page ? PVKVM_MEMORY_LEN : 0, m + PVKVM_DATA_SIZE_AT);
	writel(command, m + PVKVM_COMMAND_AT);
	wmb();
	writel(seq, m + PVKVM_REQUEST_AT);
	writel(PVKVM_HOST_VECTOR, provider->doorbell + PVKVM_DOORBELL_AT);
	if (command == PVKVM_RUN)
		waited = wait_event_interruptible_timeout(provider->replied,
				atomic_read(&provider->interrupt_count) != interrupts &&
				readl(m + PVKVM_REPLY_AT) == seq, 5 * HZ);
	else
		waited = wait_event_timeout(provider->replied,
				atomic_read(&provider->interrupt_count) != interrupts &&
				readl(m + PVKVM_REPLY_AT) == seq, 5 * HZ);
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
	if (!status && page) {
		memcpy_fromio(page, m + PVKVM_MEMORY_AT, PVKVM_MEMORY_LEN);
		*io_value = readl(m + PVKVM_IO_VALUE_AT);
	}
	return status;
}

static void close_object(struct pvkvm *p, enum pvkvm_command command)
{
	if (request(p, command, NULL, NULL))
		p->dead = true;
}

static void provider_free(struct kref *ref)
{
	kfree(container_of(ref, struct pvkvm, refs));
}

static void vm_free(struct kref *ref)
{
	struct pvvm *vm = container_of(ref, struct pvvm, refs);
	struct pvkvm *p = vm->provider;

	mutex_lock(&p->lock);
	close_object(p, PVKVM_CLOSE_VM);
	p->vm_open = false;
	mutex_unlock(&p->lock);
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
	close_object(p, PVKVM_CLOSE_VCPU);
	vm->cpu_open = false;
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

static int run_cpu(struct pvcpu *cpu)
{
	struct pvvm *vm = cpu->vm;
	struct pvkvm *p = vm->provider;
	void __user *buffer;
	void *bytes;
	int result;

	result = mutex_lock_interruptible(&p->lock);
	if (result)
		return -EINTR;
	if (signal_pending(current)) {
		result = -EINTR;
		goto unlock;
	}
	if (!vm->userspace_addr) {
		result = -EINVAL;
		goto unlock;
	}
	buffer = u64_to_user_ptr(vm->userspace_addr);
	bytes = memdup_user(buffer, PVKVM_MEMORY_LEN);
	if (IS_ERR(bytes)) {
		result = PTR_ERR(bytes);
		goto unlock;
	}
	result = request(p, PVKVM_RUN, bytes, &cpu->page->data);
	if (!result) {
		cpu->ran = true;
		if (copy_to_user(buffer, bytes, PVKVM_MEMORY_LEN))
			result = -EFAULT;
	}
	kfree(bytes);
unlock:
	mutex_unlock(&p->lock);
	return result;
}

static long cpu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pvcpu *cpu = file->private_data;
	struct run_page *page = cpu->page;
	struct kvm_sregs sregs, wanted;
	struct kvm_regs regs;
	void __user *uarg = (void __user *)arg;
	long result;

	if (cpu->vm->owner != current->mm)
		return -EIO;
	result = mutex_lock_interruptible(&cpu->execution);
	if (result)
		return -EINTR;
	if (cpu->ran && cmd != KVM_RUN) {
		mutex_unlock(&cpu->execution);
		return -EOPNOTSUPP;
	}
	switch (cmd) {
	case KVM_GET_REGS:
		result = copy_to_user(uarg, &cpu->regs, sizeof(cpu->regs)) ? -EFAULT : 0;
		break;
	case KVM_SET_REGS:
		if (copy_from_user(&regs, uarg, sizeof(regs))) {
			result = -EFAULT;
			break;
		}
		if (memcmp(&regs, &entry_regs, sizeof(regs))) {
			result = -EINVAL;
			break;
		}
		cpu->regs = regs;
		result = 0;
		break;
	case KVM_GET_SREGS:
		result = copy_to_user(uarg, &cpu->sregs, sizeof(cpu->sregs)) ? -EFAULT : 0;
		break;
	case KVM_SET_SREGS:
		if (copy_from_user(&sregs, uarg, sizeof(sregs))) {
			result = -EFAULT;
			break;
		}
		wanted = reset_sregs;
		wanted.cs.base = 0;
		wanted.cs.selector = 0;
		if (memcmp(&sregs, &wanted, sizeof(sregs))) {
			result = -EINVAL;
			break;
		}
		cpu->sregs = sregs;
		result = 0;
		break;
	case KVM_RUN:
		if (arg || cpu->regs.rip != PVKVM_GUEST_START || cpu->sregs.cs.base) {
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

	if (id)
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
	cpu->regs.rip = 0xfff0;
	cpu->regs.rflags = 2;
	cpu->sregs = reset_sregs;
	mutex_init(&cpu->execution);
	mutex_lock(&p->lock);
	fd = vm->cpu_open ? -EEXIST : request(p, PVKVM_CREATE_VCPU, NULL, NULL);
	if (!fd) {
		fd = anon_inode_getfd("flexvm-vcpu", &cpu_fops, cpu, O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			close_object(p, PVKVM_CLOSE_VCPU);
		} else {
			vm->cpu_open = true;
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

static long vm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pvvm *vm = file->private_data;
	struct pvkvm *p = vm->provider;
	struct kvm_userspace_memory_region memory;
	int result;

	if (vm->owner != current->mm)
		return -EIO;
	if (cmd == KVM_CREATE_VCPU)
		return new_cpu(vm, arg);
	if (cmd != KVM_SET_USER_MEMORY_REGION)
		return -ENOTTY;
	if (copy_from_user(&memory, (void __user *)arg, sizeof(memory)))
		return -EFAULT;
	if (memory.slot || memory.flags || memory.guest_phys_addr != PVKVM_GUEST_START ||
	    memory.memory_size != PVKVM_MEMORY_LEN || !memory.userspace_addr ||
	    !PAGE_ALIGNED(memory.userspace_addr))
		return -EINVAL;
	mutex_lock(&p->lock);
	result = p->dead ? -ENODEV : 0;
	if (!result)
		vm->userspace_addr = memory.userspace_addr;
	mutex_unlock(&p->lock);
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
	fd = p->vm_open ? -EBUSY : request(p, PVKVM_CREATE_VM, NULL, NULL);
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
		return 0;
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
	if (pci_resource_len(dev, 0) < PVKVM_DOORBELL_AT + sizeof(u32) ||
	    pci_resource_len(dev, 2) < PVKVM_MEMORY_AT + PVKVM_MEMORY_LEN)
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
