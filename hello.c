
#include <linux/kernel.h>	/* Needed for KERN_INFO */
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
 #include <linux/buffer_head.h>
 #include <linux/backing-dev.h>
 #include <linux/pagevec.h>
 #include <linux/migrate.h>
 #include <linux/page-flags.h>
  #include <asm/pgtable.h>
 

 #include <asm/tlbflush.h>
 #include "internal.h"
 
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
 
 /**
  * struct ksm_scan - cursor for scanning
  * @mm_slot: the current mm_slot we are scanning
  * @address: the next address inside that to be scanned
  * @rmap_list: link to the next rmap to be scanned in the rmap_list
  * @seqnr: count of completed full scans (needed when removing unstable node)
  *
  * There is only the one ksm_scan instance of this cursor structure.
  */
 struct ksm_scan {
         struct mm_slot *mm_slot;
         unsigned long address;
         struct rmap_item **rmap_list;
         unsigned long seqnr;
 };
 
 /**
  * struct stable_node - node of the stable rbtree
  * @node: rb node of this ksm page in the stable tree
  * @head: (overlaying parent) &migrate_nodes indicates temporarily on that list
  * @list: linked into migrate_nodes, pending placement in the proper node tree
  * @hlist: hlist head of rmap_items using this ksm page
  * @kpfn: page frame number of this ksm page (perhaps temporarily on wrong nid)
  * @nid: NUMA node id of stable tree in which linked (may not match kpfn)
  */
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
 
 /**
  * struct rmap_item - reverse mapping item for virtual addresses
  * @rmap_list: next rmap_item in mm_slot's singly-linked rmap_list
  * @anon_vma: pointer to anon_vma for this mm,address, when in stable tree
  * @nid: NUMA node id of unstable tree in which linked (may not match page)
  * @mm: the memory structure this rmap_item is pointing into
  * @address: the virtual address this rmap_item tracks (+ flags in low bits)
  * @oldchecksum: previous checksum of the page at that virtual address
  * @node: rb node of this rmap_item in the unstable tree
  * @head: pointer to stable_node heading this list in the stable tree
  * @hlist: link into hlist of rmap_items hanging off that stable_node
  */
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

 static struct rb_root one_stable_tree[1] = { RB_ROOT };
 static struct rb_root one_unstable_tree[1] = { RB_ROOT };
 static struct rb_root *root_stable_tree = one_stable_tree;
 static struct rb_root *root_unstable_tree = one_unstable_tree;
 static struct stable_node *test_stable;
 static struct mm_slot *test_mm_slot;
 
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

struct rmap_item * rmap_items;
 
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
         //remove_node_from_stable_tree(stable_node);
         return NULL;
 }

int init_module(void)
{
	printk(KERN_INFO "Hello world 1.\n");
	ksm_slab_init();
	test_stable = alloc_stable_node();
	//get_ksm_page(test_stable, 0);
	//test_mm_slot = alloc_mm_slot();
	printk(KERN_INFO "Still fine.\n");
	/* 
	 * A non 0 return means init_module failed; module can't be loaded. 
	 */
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "kpfn: %d", (*(test_stable)).kpfn);
	//free_rmap_item(test_stable);
	//printk(KERN_INFO "kpfn: %d", (*(test_mm_slot)).kpfn);
	//free_mm_slot(test_mm_slot);
	//printk(KERN_INFO "kpfn: %d", ksm_scan.address);
	ksm_slab_free();
	printk(KERN_INFO "Exit.\n");
	printk(KERN_INFO "Goodbye world 1.\n");
}