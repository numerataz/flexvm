/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLEXVM_ARM_FRONTEND_H
#define FLEXVM_ARM_FRONTEND_H

static long arm_preferred_target(struct pvvm *vm, struct kvm_vcpu_init __user *user)
{
	struct pvkvm *p = vm->provider;
	struct kvm_vcpu_init init;
	int status = mutex_lock_interruptible(&p->lock);

	if (status)
		return status;
	status = request(p, PVKVM_ARM_PREFERRED_TARGET, NULL, NULL);
	if (!status)
		memcpy_fromio(&init, p->mailbox + PVKVM_ARM_INIT_AT, sizeof(init));
	mutex_unlock(&p->lock);
	if (!status && copy_to_user(user, &init, sizeof(init)))
		return -EFAULT;
	return status;
}

static long arm_init_cpu(struct pvcpu *cpu, struct kvm_vcpu_init __user *user)
{
	struct pvkvm *p = cpu->vm->provider;
	struct kvm_vcpu_init init;
	int status;

	if (copy_from_user(&init, user, sizeof(init)))
		return -EFAULT;
	status = mutex_lock_interruptible(&p->lock);
	if (status)
		return status;
	if (READ_ONCE(p->dead)) {
		status = -ENODEV;
	} else {
		memcpy_toio(p->mailbox + PVKVM_ARM_INIT_AT, &init, sizeof(init));
		status = request_for_cpu(cpu, PVKVM_ARM_INIT_VCPU, NULL, NULL);
		if (!status) {
			cpu->initialized = true;
			cpu->read_bytes = 0;
		}
	}
	mutex_unlock(&p->lock);
	return status;
}

static long arm_register(struct pvcpu *cpu, bool write, struct kvm_one_reg __user *user)
{
	struct pvkvm *p = cpu->vm->provider;
	struct kvm_one_reg reg;
	struct pvkvm_arm_register record = {};
	size_t bytes;
	int status;

	if (copy_from_user(&reg, user, sizeof(reg)))
		return -EFAULT;
	bytes = KVM_REG_SIZE(reg.id);
	if (bytes > sizeof(record.data))
		return -EOPNOTSUPP;
	record.id = reg.id;
	if (write && copy_from_user(record.data, u64_to_user_ptr(reg.addr), bytes))
		return -EFAULT;
	status = mutex_lock_interruptible(&p->lock);
	if (status)
		return status;
	if (READ_ONCE(p->dead)) {
		status = -ENODEV;
	} else {
		void __iomem *location = p->mailbox + PVKVM_ARM_REG_AT;

		memcpy_toio(location, &record, sizeof(record));
		status = request_for_cpu(cpu, write ? PVKVM_ARM_SET_ONE_REG : PVKVM_ARM_GET_ONE_REG, NULL, NULL);
		if (!status && !write)
			memcpy_fromio(record.data, location + offsetof(struct pvkvm_arm_register, data), bytes);
	}
	mutex_unlock(&p->lock);
	if (!status && !write && copy_to_user(u64_to_user_ptr(reg.addr), record.data, bytes))
		return -EFAULT;
	return status;
}

static long arm_register_list(struct pvcpu *cpu, struct kvm_reg_list __user *user)
{
	struct pvkvm *p = cpu->vm->provider;
	u64 capacity, count = 0;
	u64 *ids;
	int status;

	if (get_user(capacity, &user->n))
		return -EFAULT;
	capacity = min_t(u64, capacity, PVKVM_ARM_MAX_REGS);
	ids = kvmalloc_array(capacity, sizeof(*ids), GFP_KERNEL);
	if (!ids)
		return -ENOMEM;
	status = mutex_lock_interruptible(&p->lock);
	if (status)
		goto free_ids;
	if (READ_ONCE(p->dead)) {
		status = -ENODEV;
	} else {
		void __iomem *location = p->mailbox + PVKVM_ARM_REGS_AT;

		writeq(capacity, location);
		status = request_for_cpu(cpu, PVKVM_ARM_GET_REG_LIST, NULL, NULL);
		if (!status || status == -E2BIG)
			count = readq(location);
		if (!status && count > capacity)
			status = -EIO;
		else if (!status && count)
			memcpy_fromio(ids, location + sizeof(u64), count * sizeof(*ids));
	}
	mutex_unlock(&p->lock);
	if ((!status || status == -E2BIG) && put_user(count, &user->n))
		status = -EFAULT;
	if (!status && count && copy_to_user(user->reg, ids, count * sizeof(*ids)))
		status = -EFAULT;
free_ids:
	kvfree(ids);
	return status;
}

static long cpu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pvcpu *cpu = file->private_data;
	void __user *user = (void __user *)arg;
	long status;

	if (cpu->vm->owner != current->mm)
		return -EIO;
	status = cmd == KVM_RUN ? mutex_lock_killable(&cpu->execution) :
				 mutex_lock_interruptible(&cpu->execution);
	if (status)
		return -EINTR;
	if (cmd == KVM_ARM_VCPU_INIT) {
		status = arm_init_cpu(cpu, user);
	} else if (!cpu->initialized) {
		status = -ENOEXEC;
	} else {
		switch (cmd) {
		case KVM_GET_REG_LIST:
			status = arm_register_list(cpu, user);
			break;
		case KVM_GET_ONE_REG:
		case KVM_SET_ONE_REG:
			status = arm_register(cpu, cmd == KVM_SET_ONE_REG, user);
			break;
		case KVM_RUN:
			status = arg ? -EINVAL : run_cpu(cpu);
			break;
		default:
			status = -ENOTTY;
		}
	}
	mutex_unlock(&cpu->execution);
	return status;
}

#endif
