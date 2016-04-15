#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/rwsem.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/memory.h>
#include <linux/mmu_notifier.h>
#include <linux/swap.h>
#include <linux/ksm.h>
#include <linux/hashtable.h>
#include <linux/freezer.h>
#include <linux/oom.h>
#include <linux/numa.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <asm/tlbflush.h>
#include "internal.h"

#include <linux/init.h>		/* __init and __exit macroses */
#include <linux/kernel.h>	/* KERN_INFO macros */
#include <linux/module.h>	/* required for all kernel modules */
#include <linux/moduleparam.h>	/* module_param() and MODULE_PARM_DESC() */

#include <linux/miscdevice.h>	/* struct miscdevice and misc_[de]register() */
#include <linux/mutex.h>	/* mutexes */
#include <linux/string.h>	/* memchr() function */
#include <linux/slab.h>		/* kzalloc() function */
#include <linux/sched.h>	/* wait queues */
#include <linux/uaccess.h>	/* copy_{to,from}_user() */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("oat9002");
MODULE_DESCRIPTION("In-kernel memaudit");

static unsigned long buffer_size = 8192;

struct buffer {
	wait_queue_head_t read_queue;
	struct mutex lock;
	char *data, *end;
	char *read_ptr;
	unsigned long size;
};

static struct file_operations memaudit_fops = {
	.owner = THIS_MODULE,
	.open = memaudit_open,
	.read = memaudit_read,
	.write = memaudit_write,
	.release = memaudit_close,
};

static struct miscdevice memaudit_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "memaudit",
	.fops = &memaudit_fops
};

static struct buffer *buffer_alloc(unsigned long size)
{
	struct buffer *buf = NULL;

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (unlikely(!buf))
		goto out;

	buf->data = kzalloc(size, GFP_KERNEL);
	if (unlikely(!buf->data))
		goto out_free;

	init_waitqueue_head(&buf->read_queue);

	mutex_init(&buf->lock);

	/* It's unused for now, but may appear useful later */
	buf->size = size;

 out:
	return buf;

 out_free:
	kfree(buf);
	return NULL;
}

static void buffer_free(struct buffer *buffer)
{
	kfree(buffer->data);
	kfree(buffer);
}

static int __init memaudit_init(void)
{
	if(!buffer_size)
		return -1;
	misc_register(&memaudit_misc_device);
	printk(KERN_INFO "memaudit device has been registered, buffer size is %lu bytes\n", buffer_size);
	return 0;
}

static void __exit memaudit_exit(void)
{
	misc_deregister(&memaudit_misc_device);
	printk(KERN_INFO "memaudit device has been unregisterd\n");
}

module_init(memaudit_init);
module_exit(memaudit_exit);
