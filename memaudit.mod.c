#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x6c15661c, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x792b8d85, __VMLINUX_SYMBOL_STR(misc_deregister) },
	{ 0xcec25ecf, __VMLINUX_SYMBOL_STR(misc_register) },
	{ 0xa770832, __VMLINUX_SYMBOL_STR(register_memory_notifier) },
	{ 0xfa509c21, __VMLINUX_SYMBOL_STR(kthread_stop) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xf7b6fbdd, __VMLINUX_SYMBOL_STR(sysfs_create_group) },
	{ 0xab62cab5, __VMLINUX_SYMBOL_STR(mm_kobj) },
	{ 0x2d530ebc, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0x649a4c3b, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0x40d836d8, __VMLINUX_SYMBOL_STR(kmem_cache_destroy) },
	{ 0xaf08e37a, __VMLINUX_SYMBOL_STR(kmem_cache_create) },
	{ 0x33b84f74, __VMLINUX_SYMBOL_STR(copy_page) },
	{ 0x618911fc, __VMLINUX_SYMBOL_STR(numa_node) },
	{ 0xf16a81e3, __VMLINUX_SYMBOL_STR(up_write) },
	{ 0xe04bc64d, __VMLINUX_SYMBOL_STR(down_write) },
	{ 0x7fe32873, __VMLINUX_SYMBOL_STR(rb_replace_node) },
	{ 0x4482cdb, __VMLINUX_SYMBOL_STR(__refrigerator) },
	{ 0x10c3ab5e, __VMLINUX_SYMBOL_STR(freezing_slow_path) },
	{ 0xa5526619, __VMLINUX_SYMBOL_STR(rb_insert_color) },
	{ 0xc1376644, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0x9c55cec, __VMLINUX_SYMBOL_STR(schedule_timeout_interruptible) },
	{ 0x7f02188f, __VMLINUX_SYMBOL_STR(__msecs_to_jiffies) },
	{ 0x7ab88a45, __VMLINUX_SYMBOL_STR(system_freezing_cnt) },
	{ 0xb3f7646e, __VMLINUX_SYMBOL_STR(kthread_should_stop) },
	{ 0xfa7f66b8, __VMLINUX_SYMBOL_STR(set_user_nice) },
	{ 0x9e61bb05, __VMLINUX_SYMBOL_STR(set_freezable) },
	{ 0xcf48d069, __VMLINUX_SYMBOL_STR(__get_page_tail) },
	{ 0xc512626a, __VMLINUX_SYMBOL_STR(__supported_pte_mask) },
	{ 0x50b94154, __VMLINUX_SYMBOL_STR(set_page_dirty) },
	{ 0x6efb31ae, __VMLINUX_SYMBOL_STR(__mmu_notifier_invalidate_range) },
	{ 0xed75f848, __VMLINUX_SYMBOL_STR(mark_page_accessed) },
	{ 0x152353ec, __VMLINUX_SYMBOL_STR(__mmu_notifier_invalidate_range_start) },
	{ 0x870757b4, __VMLINUX_SYMBOL_STR(__mmu_notifier_invalidate_range_end) },
	{ 0x58e83f2d, __VMLINUX_SYMBOL_STR(pv_mmu_ops) },
	{ 0x22797a41, __VMLINUX_SYMBOL_STR(__mmdrop) },
	{ 0x6bf1c17f, __VMLINUX_SYMBOL_STR(pv_lock_ops) },
	{ 0xe259ae9e, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0xfe26fc7c, __VMLINUX_SYMBOL_STR(nr_node_ids) },
	{ 0x6fcb104f, __VMLINUX_SYMBOL_STR(__lock_page) },
	{ 0x138f72ab, __VMLINUX_SYMBOL_STR(unlock_page) },
	{ 0x5f37af31, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x9e88526, __VMLINUX_SYMBOL_STR(__init_waitqueue_head) },
	{ 0xb4f22726, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x3a40aaab, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x449ad0a7, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0xbfadf02e, __VMLINUX_SYMBOL_STR(up_read) },
	{ 0x9fe102f5, __VMLINUX_SYMBOL_STR(down_read) },
	{ 0xca9360b5, __VMLINUX_SYMBOL_STR(rb_next) },
	{ 0xece784c2, __VMLINUX_SYMBOL_STR(rb_first) },
	{ 0xa0fbac79, __VMLINUX_SYMBOL_STR(wake_up_bit) },
	{ 0x48e03c9c, __VMLINUX_SYMBOL_STR(kmem_cache_free) },
	{ 0x4d9b652b, __VMLINUX_SYMBOL_STR(rb_erase) },
	{ 0xc5092e89, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0xe8a73aaf, __VMLINUX_SYMBOL_STR(out_of_line_wait_on_bit) },
	{ 0x16e297c3, __VMLINUX_SYMBOL_STR(bit_wait) },
	{ 0x322c2b93, __VMLINUX_SYMBOL_STR(find_vma) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x3c80c06c, __VMLINUX_SYMBOL_STR(kstrtoull) },
	{ 0x4f8b5ddb, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0xf08242c2, __VMLINUX_SYMBOL_STR(finish_wait) },
	{ 0x2207a57f, __VMLINUX_SYMBOL_STR(prepare_to_wait_event) },
	{ 0x1000e51, __VMLINUX_SYMBOL_STR(schedule) },
	{ 0xa6bbd805, __VMLINUX_SYMBOL_STR(__wake_up) },
	{ 0x8ca05263, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0x4f6b400b, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0x1ad241df, __VMLINUX_SYMBOL_STR(mutex_lock_interruptible) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xb713117a, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xb107f5f6, __VMLINUX_SYMBOL_STR(handle_mm_fault) },
	{ 0xf45fb4fd, __VMLINUX_SYMBOL_STR(put_page) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "D8BC19D746997CBD3372979");
