// SPDX-License-Identifier: GPL-2.0-only
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>

extern void flexvm_test_sample(u64 *identity, u64 *count);

static ssize_t sample(struct file *file, char __user *buffer, size_t length, loff_t *offset)
{
	char text[64];
	u64 identity, count;
	int size;

	flexvm_test_sample(&identity, &count);
	size = scnprintf(text, sizeof(text), "%llu %llu\n", identity, count);
	return simple_read_from_buffer(buffer, length, offset, text, size);
}

static const struct file_operations operations = {
	.owner = THIS_MODULE,
	.read = sample,
	.llseek = no_llseek,
};

static struct miscdevice device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "flexvm-module-test",
	.fops = &operations,
	.mode = 0600,
};

static int __init device_init(void)
{
	return misc_register(&device);
}

static void __exit device_exit(void)
{
	misc_deregister(&device);
}

module_init(device_init);
module_exit(device_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FlexVM guest-only module dependency and device fixture");
