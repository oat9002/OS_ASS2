#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/ksm.h>

#include <linux/init.h>		/* __init and __exit macroses */
#include <linux/kernel.h>	/* KERN_INFO macros */
#include <linux/moduleparam.h>	/* module_param() and MODULE_PARM_DESC() */

#include <linux/fs.h>		/* struct file_operations, struct file */
#include <linux/miscdevice.h>	/* struct miscdevice and misc_[de]register() */
#include <linux/mutex.h>	/* mutexes */
#include <linux/string.h>	/* memchr() function */
#include <linux/slab.h>		/* kzalloc() function */
#include <linux/sched.h>	/* wait queues */
#include <linux/uaccess.h>	/* copy_{to,from}_user() */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("oat");
MODULE_DESCRIPTION("In-kernel memaudit");

static unsigned long buffer_size = 1024;

struct buffer {
	wait_queue_head_t read_queue;
	struct mutex lock;
	char *data, *end;
	char *read_ptr;
	unsigned long size;
};


// from monthon //
static struct page *walk_page_table(struct mm_struct *memory,unsigned long addr,struct task_struct *task)
{
    pgd_t *pgd;
    pte_t *ptep, pte;
    pud_t *pud;
    pmd_t *pmd;

    struct page *page = NULL;
    struct mm_struct *mm = memory;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto out;
    //printk(KERN_NOTICE "Valid pgd");

    pud = pud_offset(pgd, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto out;
    //printk(KERN_NOTICE "Valid pud");

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto out;
    //printk(KERN_NOTICE "Valid pmd");

    ptep = pte_offset_map(pmd, addr);
    if (!ptep)
        goto out;
    pte = *ptep;

    page = pte_page(pte);
    if (page){
        //if(pte_write(pte)){
            //printk(KERN_INFO "page can read @ \n");
            //printk(KERN_INFO "page frame struct is page write@ %lx\n", pte_write(pte));
        char *addr1;
        addr1 = kmap_atomic(page);
        printk(KERN_INFO "page frame struct is page val PID [%d]  \n",task->pid);

        printk(KERN_INFO "page frame struct is page val %s \n", addr1);
        //printk(KERN_INFO "page frame struct is page val@ %lx\n", addr1);
        kunmap_atomic(addr1);
   //print_code(mm->start_code,mm->end_code);
    }
    pte_unmap(ptep);
    out:
    return page;
}

static void findword(unsigned long vpage,unsigned long start_addr,unsigned long stop_addr,struct task_struct *task, unsigned long *count_page){
	if(vpage>=start_addr && vpage <=stop_addr) {
		struct page *page_pte = walk_page_table(task->mm,vpage,task);
        	if(page_pte) {
        		printk("page can read \n");
                        *count_page += 1;
        	}
        	else {
        		printk("page cannot read \n");
                }
        }
}

static void print_total_page(struct task_struct *task,unsigned long *count_page)
{
	struct vm_area_struct *vma = 0;
	unsigned long vpage;
    	//pointer_t buf;
    	//uint32_t sz;
    	if (task->mm && task->mm->mmap) {
        	for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
            		for (vpage = vma->vm_start; vpage < vma->vm_end; vpage += PAGE_SIZE){
                		findword(vpage,task->mm->start_code,task->mm->end_code,task,count_page);
                		findword(vpage,task->mm->start_data,task->mm->end_data,task,count_page);
                		findword(vpage,task->mm->start_brk,task->mm->brk,task,count_page);
            		}
        	}
	}
   }
////////////////////

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

static int memaudit_open(struct inode *inode, struct file *file)
{
	struct buffer *buf;
	int err = 0;

	/*
	 * Real code can use inode to get pointer to the private
	 * device state.
	 */

	buf = buffer_alloc(buffer_size);
	if (unlikely(!buf)) {
		err = -ENOMEM;
		goto out;
	}

	file->private_data = buf;

 out:
	return err;
}

static ssize_t memaudit_read(struct file *file, char __user * out, size_t size, loff_t * off)
{
	struct buffer *buf = file->private_data;
	ssize_t result;

	if (mutex_lock_interruptible(&buf->lock)) {
		result = -ERESTARTSYS;
		goto out;
	}

	while (buf->read_ptr == buf->end) {
		mutex_unlock(&buf->lock);
		if (file->f_flags & O_NONBLOCK) {
			result = -EAGAIN;
			goto out;
		}
		if (wait_event_interruptible(buf->read_queue, buf->read_ptr != buf->end)) {
			result = -ERESTARTSYS;
			goto out;
		}
		if (mutex_lock_interruptible(&buf->lock)) {
			result = -ERESTARTSYS;
			goto out;
		}
	}

	size = min(size, (size_t) (buf->end - buf->read_ptr));
	if (copy_to_user(out, buf->read_ptr, size)) {
		result = -EFAULT;
		goto out_unlock;
	}

	buf->read_ptr += size;
	result = size;

 out_unlock:
	mutex_unlock(&buf->lock);
 out:
	return result;
}

static ssize_t memaudit_write(struct file *file, const char __user * in, size_t size, loff_t * off)
{
	struct buffer *buf = file->private_data;
	ssize_t result;

	if (size > buffer_size) {
		result = -EFBIG;
		goto out;
	}

	if (mutex_lock_interruptible(&buf->lock)) {
		result = -ERESTARTSYS;
		goto out;
	}

	if (copy_from_user(buf->data, in, size)) {
		result = -EFAULT;
		goto out_unlock;
	}

	buf->end = buf->data + size;
	buf->read_ptr = buf->data;

	wake_up_interruptible(&buf->read_queue);

	result = size;
 out_unlock:
	mutex_unlock(&buf->lock);
 out:
	return result;
}

static int memaudit_close(struct inode *inode, struct file *file)
{
	struct buffer *buf = file->private_data;
	//buffer_free(buf);
	return 0;
}

static struct file_operations memaudit_fops = {
	.owner = THIS_MODULE,
	.open = memaudit_open,
	.read = memaudit_read,
	.write = memaudit_write,
	.release = memaudit_close,
	.llseek = noop_llseek
};

static struct miscdevice memaudit_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "memaudit",
	.fops = &memaudit_fops
};

static int __init memaudit_init(void)
{
	struct task_struct *task;

	// check buffer size is not null
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
