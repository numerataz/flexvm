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

static long arm_mp_state(struct pvcpu *cpu, bool write, struct kvm_mp_state __user *user)
{
	struct pvkvm *p = cpu->vm->provider;
	struct kvm_mp_state state;
	int status;

	if (write && copy_from_user(&state, user, sizeof(state)))
		return -EFAULT;
	status = mutex_lock_interruptible(&p->lock);
	if (status)
		return status;
	if (READ_ONCE(p->dead)) {
		status = -ENODEV;
	} else {
		void __iomem *location = p->mailbox + PVKVM_ARM_MP_STATE_AT;

		if (write)
			memcpy_toio(location, &state, sizeof(state));
		status = request_for_cpu(cpu, write ? PVKVM_ARM_SET_MP_STATE : PVKVM_ARM_GET_MP_STATE, NULL, NULL);
		if (!status && !write)
			memcpy_fromio(&state, location, sizeof(state));
	}
	mutex_unlock(&p->lock);
	if (!status && !write && copy_to_user(user, &state, sizeof(state)))
		return -EFAULT;
	return status;
}

static int arm_bind_irqfd(struct pvvm *vm, u32 gsi)
{
	struct pvkvm *p = vm->provider;
	int status = mutex_lock_interruptible(&p->lock);

	if (status)
		return status;
	if (READ_ONCE(p->dead)) {
		status = -ENODEV;
	} else {
		writel(gsi, p->mailbox + PVKVM_ARM_GSI_AT);
		status = request(p, PVKVM_ARM_BIND_IRQFD, NULL, NULL);
	}
	mutex_unlock(&p->lock);
	return status;
}

struct arm_device {
	struct pvvm *vm;
	u32 type;
};

static int arm_device_request(struct pvvm *vm, enum pvkvm_command command, struct pvkvm_arm_device *record)
{
	struct pvkvm *p = vm->provider;
	int status;

	mutex_lock(&p->lock);
	if (READ_ONCE(p->dead)) {
		status = -ENODEV;
	} else {
		void __iomem *location = p->mailbox + PVKVM_ARM_DEVICE_AT;

		memcpy_toio(location, record, sizeof(*record));
		status = request(p, command, NULL, NULL);
		if (!status && command == PVKVM_ARM_GET_DEVICE_ATTR)
			record->value = readq(location + offsetof(struct pvkvm_arm_device, value));
	}
	mutex_unlock(&p->lock);
	return status;
}

static int arm_device_release(struct inode *inode, struct file *file)
{
	struct arm_device *device = file->private_data;
	struct pvkvm_arm_device record = { .type = device->type };

	if (arm_device_request(device->vm, PVKVM_ARM_CLOSE_DEVICE, &record))
		mark_provider_dead(device->vm->provider);
	kref_put(&device->vm->refs, vm_free);
	kfree(device);
	return 0;
}

static long arm_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct arm_device *device = file->private_data;
	struct kvm_device_attr attribute;
	struct pvkvm_arm_device record = { .type = device->type };
	enum pvkvm_command command;
	int bytes, status;

	if (device->vm->owner != current->mm)
		return -EIO;
	switch (cmd) {
	case KVM_GET_DEVICE_ATTR:
		command = PVKVM_ARM_GET_DEVICE_ATTR;
		break;
	case KVM_SET_DEVICE_ATTR:
		command = PVKVM_ARM_SET_DEVICE_ATTR;
		break;
	case KVM_HAS_DEVICE_ATTR:
		command = PVKVM_ARM_HAS_DEVICE_ATTR;
		break;
	default:
		return -ENOTTY;
	}
	if (copy_from_user(&attribute, (void __user *)arg, sizeof(attribute)))
		return -EFAULT;
	bytes = arm_vgic_attribute_size(device->type, attribute.group, attribute.attr);
	if (bytes < 0 || attribute.flags || (!bytes && cmd == KVM_GET_DEVICE_ATTR))
		return -ENXIO;
	record.group = attribute.group;
	record.attribute = attribute.attr;
	if (cmd == KVM_SET_DEVICE_ATTR && bytes &&
	    copy_from_user(&record.value, u64_to_user_ptr(attribute.addr), bytes))
		return -EFAULT;
	status = arm_device_request(device->vm, command, &record);
	if (!status && cmd == KVM_GET_DEVICE_ATTR &&
	    copy_to_user(u64_to_user_ptr(attribute.addr), &record.value, bytes))
		return -EFAULT;
	if (!status && cmd == KVM_SET_DEVICE_ATTR && !bytes && device->type == KVM_DEV_TYPE_ARM_VGIC_V3)
		WRITE_ONCE(device->vm->irqchip_created, true);
	return status;
}

static const struct file_operations arm_device_fops = {
	.owner = THIS_MODULE,
	.release = arm_device_release,
	.unlocked_ioctl = arm_device_ioctl,
};

static long arm_create_device(struct pvvm *vm, struct kvm_create_device __user *user)
{
	struct kvm_create_device create;
	struct pvkvm_arm_device record = {};
	struct arm_device *device;
	struct file *file;
	int fd, status;

	if (copy_from_user(&create, user, sizeof(create)))
		return -EFAULT;
	if (create.flags & ~KVM_CREATE_DEVICE_TEST)
		return -EINVAL;
	if (arm_vgic_index(create.type) < 0)
		return -ENODEV;
	record.type = create.type;
	record.flags = create.flags;
	if (create.flags & KVM_CREATE_DEVICE_TEST)
		return arm_device_request(vm, PVKVM_ARM_CREATE_DEVICE, &record);
	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		return -ENOMEM;
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		kfree(device);
		return fd;
	}
	status = arm_device_request(vm, PVKVM_ARM_CREATE_DEVICE, &record);
	if (status)
		goto release_fd;
	device->vm = vm;
	device->type = create.type;
	file = anon_inode_getfile("flexvm-arm-vgic", &arm_device_fops, device, O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)) {
		status = PTR_ERR(file);
		if (arm_device_request(vm, PVKVM_ARM_CLOSE_DEVICE, &record))
			mark_provider_dead(vm->provider);
		goto release_fd;
	}
	kref_get(&vm->refs);
	create.fd = fd;
	if (copy_to_user(user, &create, sizeof(create))) {
		fput(file);
		put_unused_fd(fd);
		return -EFAULT;
	}
	fd_install(fd, file);
	return 0;

release_fd:
	put_unused_fd(fd);
	kfree(device);
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
		case KVM_GET_MP_STATE:
		case KVM_SET_MP_STATE:
			status = arm_mp_state(cpu, cmd == KVM_SET_MP_STATE, user);
			break;
		case KVM_HAS_DEVICE_ATTR:
			status = -ENXIO;
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
