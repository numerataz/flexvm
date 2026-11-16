// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/timer.h>

static unsigned long cookie;
// A new load must choose a new identity; userspace cannot seed a replay.
static atomic64_t ticks = ATOMIC64_INIT(0);
static struct timer_list timer;

void flexvm_test_sample(u64 *identity, u64 *count)
{
	*identity = cookie;
	*count = atomic64_read(&ticks);
}
EXPORT_SYMBOL_GPL(flexvm_test_sample);

static void tick(struct timer_list *unused)
{
	atomic64_inc(&ticks);
	mod_timer(&timer, jiffies + max(1UL, HZ / 10));
}

static int __init state_init(void)
{
	get_random_bytes(&cookie, sizeof(cookie));
	timer_setup(&timer, tick, 0);
	mod_timer(&timer, jiffies + max(1UL, HZ / 10));
	return 0;
}

static void __exit state_exit(void)
{
	del_timer_sync(&timer);
}

module_init(state_init);
module_exit(state_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FlexVM guest-only module state and timer continuity fixture");
