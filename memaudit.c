#include <linux/init.h>
#include <linux/module.h>
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

#include <linux/kernel_stat.h>
#include <linux/swapops.h>
#include <linux/init.h>
#include <linux/buffer_head.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/migrate.h>
#include <linux/page-flags.h>
#include <asm/pgtable.h>

#include <asm/tlbflush.h>
#include "internal.h"

#include <linux/kernel.h>	/* KERN_INFO macros */
#include <linux/moduleparam.h>	/* module_param() and MODULE_PARM_DESC() */

#include <linux/miscdevice.h>	/* struct miscdevice and misc_[de]register() */
#include <linux/mutex.h>	/* mutexes */
#include <linux/string.h>	/* memchr() function */
#include <linux/slab.h>		/* kzalloc() function */
#include <linux/sched.h>	/* wait queues */
#include <linux/uaccess.h>	/* copy_{to,from}_user() */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <asm/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("oat");
MODULE_DESCRIPTION("In-kernel memaudit");

static unsigned long buffer_size = 8192;

struct buffer {
	wait_queue_head_t read_queue;
	struct mutex lock;
	char *data, *end;
	char *read_ptr;
	unsigned long size;
};

//from ksm//
#ifdef CONFIG_NUMA
#define NUMA(x)         (x)
#define DO_NUMA(x)      do { (x); } while (0)
#else
#define NUMA(x)         (0)
#define DO_NUMA(x)      do { } while (0)
#endif

struct mm_slot {
	struct hlist_node link;
	struct list_head mm_list;
	struct rmap_item *rmap_list;
	struct mm_struct *mm;
};

struct ksm_scan {
	struct mm_slot *mm_slot;
	unsigned long address;
	struct rmap_item **rmap_list;
	unsigned long seqnr;
};

struct stable_node {
	union {
		struct rb_node node;    /* when node of stable tree */
		struct {                /* when listed for migration */
			struct list_head *head;
			struct list_head list;
		};
	};
	struct hlist_head hlist;
	unsigned long kpfn;
#ifdef CONFIG_NUMA
	int nid;
#endif
};

struct rmap_item {
	struct rmap_item *rmap_list;
	union {
		struct anon_vma *anon_vma;      /* when stable */
#ifdef CONFIG_NUMA
		int nid;                /* when node of unstable tree */
#endif
	};
	struct mm_struct *mm;
	unsigned long address;          /* + low bits used for flags below */
	unsigned int oldchecksum;       /* when unstable */
	union {
		struct rb_node node;    /* when node of unstable tree */
		struct {                /* when listed from stable tree */
			struct stable_node *head;
			struct hlist_node hlist;
		};
	};
};

#define SEQNR_MASK      0x0ff   /* low bits of unstable tree seqnr */
#define UNSTABLE_FLAG   0x100   /* is a node of the unstable tree */
#define STABLE_FLAG     0x200   /* is listed from the stable tree */

/* The stable and unstable tree heads */
static struct rb_root one_stable_tree[1] = { RB_ROOT };
static struct rb_root one_unstable_tree[1] = { RB_ROOT };
static struct rb_root *root_stable_tree = one_stable_tree;
static struct rb_root *root_unstable_tree = one_unstable_tree;

/* Recently migrated nodes of stable tree, pending proper placement */
static LIST_HEAD(migrate_nodes);

#define MM_SLOTS_HASH_BITS 10
static DEFINE_HASHTABLE(mm_slots_hash, MM_SLOTS_HASH_BITS);

static struct mm_slot ksm_mm_head = {
	.mm_list = LIST_HEAD_INIT(ksm_mm_head.mm_list),
};
static struct ksm_scan ksm_scan = {
	.mm_slot = &ksm_mm_head,
};

static struct kmem_cache *rmap_item_cache;
static struct kmem_cache *stable_node_cache;
static struct kmem_cache *mm_slot_cache;

/* The number of nodes in the stable tree */
static unsigned long ksm_pages_shared;

/* The number of page slots additionally sharing those nodes */
static unsigned long ksm_pages_sharing;

/* The number of nodes in the unstable tree */
static unsigned long ksm_pages_unshared;

/* The number of rmap_items in use: to calculate pages_volatile */
static unsigned long ksm_rmap_items;

/* Number of pages ksmd should scan in one batch */
static unsigned int ksm_thread_pages_to_scan = 100;

/* Milliseconds ksmd should sleep between batches */
static unsigned int ksm_thread_sleep_millisecs = 20;

#ifdef CONFIG_NUMA
/* Zeroed when merging across nodes is not allowed */
static unsigned int ksm_merge_across_nodes = 1;
static int ksm_nr_node_ids = 1;
#else
#define ksm_merge_across_nodes  1U
#define ksm_nr_node_ids         1
#endif

#define KSM_RUN_STOP    0
#define KSM_RUN_MERGE   1
#define KSM_RUN_UNMERGE 2
#define KSM_RUN_OFFLINE 4
static unsigned long ksm_run = KSM_RUN_STOP;
static void wait_while_offlining(void);

static DECLARE_WAIT_QUEUE_HEAD(ksm_thread_wait);
static DEFINE_MUTEX(ksm_thread_mutex);
static DEFINE_SPINLOCK(ksm_mmlist_lock);


#define KSM_KMEM_CACHE(__struct, __flags) kmem_cache_create("ksm_"#__struct,\
		sizeof(struct __struct), __alignof__(struct __struct),\
		(__flags), NULL)

static int __init ksm_slab_init(void)
{
	rmap_item_cache = KSM_KMEM_CACHE(rmap_item, 0);
	if (!rmap_item_cache)
		goto out;

	stable_node_cache = KSM_KMEM_CACHE(stable_node, 0);
	if (!stable_node_cache)
		goto out_free1;

	mm_slot_cache = KSM_KMEM_CACHE(mm_slot, 0);
	if (!mm_slot_cache)
		goto out_free2;

	return 0;

out_free2:
	kmem_cache_destroy(stable_node_cache);
out_free1:
	kmem_cache_destroy(rmap_item_cache);
out:
	return -ENOMEM;
}

static void __init ksm_slab_free(void)
{
	kmem_cache_destroy(mm_slot_cache);
	kmem_cache_destroy(stable_node_cache);
	kmem_cache_destroy(rmap_item_cache);
	mm_slot_cache = NULL;
}

static inline struct rmap_item *alloc_rmap_item(void)
{
	struct rmap_item *rmap_item;

	rmap_item = kmem_cache_zalloc(rmap_item_cache, GFP_KERNEL);
	if (rmap_item)
		ksm_rmap_items++;
	return rmap_item;
}

static inline void free_rmap_item(struct rmap_item *rmap_item)
{
	ksm_rmap_items--;
	rmap_item->mm = NULL;   /* debug safety */
	kmem_cache_free(rmap_item_cache, rmap_item);
}

static inline struct stable_node *alloc_stable_node(void)
{
	return kmem_cache_alloc(stable_node_cache, GFP_KERNEL);
}

static inline void free_stable_node(struct stable_node *stable_node)
{
	kmem_cache_free(stable_node_cache, stable_node);
}

static inline struct mm_slot *alloc_mm_slot(void)
{
	if (!mm_slot_cache)     /* initialization failed */
		return NULL;
	return kmem_cache_zalloc(mm_slot_cache, GFP_KERNEL);
}

static inline void free_mm_slot(struct mm_slot *mm_slot)
{
	kmem_cache_free(mm_slot_cache, mm_slot);
}

static struct mm_slot *get_mm_slot(struct mm_struct *mm)
{
	struct mm_slot *slot;

	hash_for_each_possible(mm_slots_hash, slot, link, (unsigned long)mm)
		if (slot->mm == mm)
			return slot;

	return NULL;
}

static inline bool ksm_test_exit(struct mm_struct *mm)
{
	return atomic_read(&mm->mm_users) == 0;
}

static void remove_node_from_stable_tree(struct stable_node *stable_node)
{
	struct rmap_item *rmap_item;

	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		if (rmap_item->hlist.next)
			ksm_pages_sharing--;
		else
			ksm_pages_shared--;
		put_anon_vma(rmap_item->anon_vma);
		rmap_item->address &= PAGE_MASK;
		cond_resched();
	}

	if (stable_node->head == &migrate_nodes)
		list_del(&stable_node->list);
	else
		rb_erase(&stable_node->node,
			 root_stable_tree + NUMA(stable_node->nid));
	free_stable_node(stable_node);
}

static struct page *get_ksm_page(struct stable_node *stable_node, bool lock_it)
{
	struct page *page;
	void *expected_mapping;
	unsigned long kpfn;

	expected_mapping = (void *)stable_node +
				(PAGE_MAPPING_ANON | PAGE_MAPPING_KSM);
again:
	kpfn = READ_ONCE(stable_node->kpfn);
	page = pfn_to_page(kpfn);

	/*
	 * page is computed from kpfn, so on most architectures reading
	 * page->mapping is naturally ordered after reading node->kpfn,
	 * but on Alpha we need to be more careful.
	 */
	smp_read_barrier_depends();
	if (READ_ONCE(page->mapping) != expected_mapping)
		goto stale;

	/*
	 * We cannot do anything with the page while its refcount is 0.
	 * Usually 0 means free, or tail of a higher-order page: in which
	 * case this node is no longer referenced, and should be freed;
	 * however, it might mean that the page is under page_freeze_refs().
	 * The __remove_mapping() case is easy, again the node is now stale;
	 * but if page is swapcache in migrate_page_move_mapping(), it might
	 * still be our page, in which case it's essential to keep the node.
	 */
	while (!get_page_unless_zero(page)) {
		/*
		 * Another check for page->mapping != expected_mapping would
		 * work here too.  We have chosen the !PageSwapCache test to
		 * optimize the common case, when the page is or is about to
		 * be freed: PageSwapCache is cleared (under spin_lock_irq)
		 * in the freeze_refs section of __remove_mapping(); but Anon
		 * page->mapping reset to NULL later, in free_pages_prepare().
		 */
		if (!PageSwapCache(page))
			goto stale;
		cpu_relax();
	}

	if (READ_ONCE(page->mapping) != expected_mapping) {
		put_page(page);
		goto stale;
	}

	if (lock_it) {
		lock_page(page);
		if (READ_ONCE(page->mapping) != expected_mapping) {
			unlock_page(page);
			put_page(page);
			goto stale;
		}
	}
	return page;

stale:
	/*
	 * We come here from above when page->mapping or !PageSwapCache
	 * suggests that the node is stale; but it might be under migration.
	 * We need smp_rmb(), matching the smp_wmb() in ksm_migrate_page(),
	 * before checking whether node->kpfn has been changed.
	 */
	smp_rmb();
	if (READ_ONCE(stable_node->kpfn) != kpfn)
		goto again;
	remove_node_from_stable_tree(stable_node);
	return NULL;
}
//////////////

// from monthon //
/*static struct page *(struct mm_struct *mm,unsigned long virt)
{
    pgd_t *pgd = pgd_offset(mm, virt);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    pud = pud_offset(pgd, virt);
    if (pud_none(*pud) || pud_bad(*pud))
        return 0;
    pmd = pmd_offset(pud, virt);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return 0;
    if (!(pte = pte_offset_map(pmd, virt)))
        return 0;
    if (!(page = pte_page(*pte)))
        return 0;
    phys = page_to_phys(page);
    pte_unmap(pte);
    return phys;
};*/

static void print_total_page(struct task_struct *task,unsigned long *count_page)
{
	struct vm_area_struct *vma = 0;
	unsigned long vpage;
	if (task->mm && task->mm->mmap) {
		for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
			 for (vpage = vma->vm_start; vpage < vma->vm_end; vpage += PAGE_SIZE){
                		//unsigned long phys = virt_to_phys(vpage);
                		//printk("%lu information\n",vpage);
                		*count_page += 1;
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
	buffer_free(buf);
	return 0;
}

static struct file_operations memaudit_fops = {
	.owner = THIS_MODULE,
	.open = memaudit_open,
	.read = memaudit_read,
	.write = memaudit_write,
	.release = memaudit_close
};

static struct miscdevice memaudit_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "memaudit",
	.fops = &memaudit_fops
};

static int __init memaudit_init(void)
{
	ksm_slab_init();

	struct task_struct *task;
        unsigned long count_page = 0;
        printk("count page start %lu \n",count_page);
        for_each_process(task){
           pr_info("%s [%d] information\n", task->comm, task->pid);
           print_total_page(task,&count_page);
       }
       printk("count page stop %lu \n",count_page);

	if(!buffer_size)
		return -1;
	misc_register(&memaudit_misc_device);
	printk(KERN_INFO "memaudit device has been registered, buffer size is %lu bytes\n", buffer_size);
	return 0;
}

static void __exit memaudit_exit(void)
{
	ksm_slab_free();
	misc_deregister(&memaudit_misc_device);
	printk(KERN_INFO "memaudit device has been unregisterd\n");
}

module_init(memaudit_init);
module_exit(memaudit_exit);
