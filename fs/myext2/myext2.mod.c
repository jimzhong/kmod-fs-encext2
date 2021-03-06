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
	{ 0x247e674, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x1f245bbb, __VMLINUX_SYMBOL_STR(crypto_alloc_skcipher) },
	{ 0x9f80223a, __VMLINUX_SYMBOL_STR(kmem_cache_destroy) },
	{ 0x479d08f, __VMLINUX_SYMBOL_STR(iget_failed) },
	{ 0x6bb04b57, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x12da5bb2, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x405c1144, __VMLINUX_SYMBOL_STR(get_seconds) },
	{ 0x2f1893bd, __VMLINUX_SYMBOL_STR(drop_nlink) },
	{ 0xfaab8b30, __VMLINUX_SYMBOL_STR(sb_min_blocksize) },
	{ 0x1bb6cf62, __VMLINUX_SYMBOL_STR(mark_buffer_dirty_inode) },
	{ 0xf104dc55, __VMLINUX_SYMBOL_STR(make_bad_inode) },
	{ 0x928a29ba, __VMLINUX_SYMBOL_STR(generic_file_llseek) },
	{ 0x38c968fd, __VMLINUX_SYMBOL_STR(__mark_inode_dirty) },
	{ 0xb8b6a76c, __VMLINUX_SYMBOL_STR(__percpu_counter_add) },
	{ 0xd6ee688f, __VMLINUX_SYMBOL_STR(vmalloc) },
	{ 0x6bf1c17f, __VMLINUX_SYMBOL_STR(pv_lock_ops) },
	{ 0x66d804b1, __VMLINUX_SYMBOL_STR(percpu_counter_destroy) },
	{ 0xd0d8621b, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x60a13e90, __VMLINUX_SYMBOL_STR(rcu_barrier) },
	{ 0xa392bb25, __VMLINUX_SYMBOL_STR(page_address) },
	{ 0xabd8fdde, __VMLINUX_SYMBOL_STR(from_kuid_munged) },
	{ 0x9d211fda, __VMLINUX_SYMBOL_STR(generic_fh_to_parent) },
	{ 0x79aa04a2, __VMLINUX_SYMBOL_STR(get_random_bytes) },
	{ 0xf3227c6b, __VMLINUX_SYMBOL_STR(block_is_partially_uptodate) },
	{ 0xefb3cb65, __VMLINUX_SYMBOL_STR(block_write_begin) },
	{ 0x67b8bc23, __VMLINUX_SYMBOL_STR(seq_puts) },
	{ 0x402756d4, __VMLINUX_SYMBOL_STR(is_bad_inode) },
	{ 0x6b7177f8, __VMLINUX_SYMBOL_STR(pagecache_get_page) },
	{ 0x25820c64, __VMLINUX_SYMBOL_STR(fs_overflowuid) },
	{ 0x1749380f, __VMLINUX_SYMBOL_STR(generic_file_open) },
	{ 0x179651ac, __VMLINUX_SYMBOL_STR(_raw_read_lock) },
	{ 0x3752af28, __VMLINUX_SYMBOL_STR(__lock_page) },
	{ 0x80985229, __VMLINUX_SYMBOL_STR(__lock_buffer) },
	{ 0x20000329, __VMLINUX_SYMBOL_STR(simple_strtoul) },
	{ 0x5a0ab78, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0xf98d5836, __VMLINUX_SYMBOL_STR(nobh_write_begin) },
	{ 0x6729d3df, __VMLINUX_SYMBOL_STR(__get_user_4) },
	{ 0x44e9a829, __VMLINUX_SYMBOL_STR(match_token) },
	{ 0x39fd8717, __VMLINUX_SYMBOL_STR(buffer_migrate_page) },
	{ 0x46b89f01, __VMLINUX_SYMBOL_STR(inc_nlink) },
	{ 0x1592615a, __VMLINUX_SYMBOL_STR(init_user_ns) },
	{ 0x5cb78f87, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0x7f6654e7, __VMLINUX_SYMBOL_STR(mount_bdev) },
	{ 0x85df9b6c, __VMLINUX_SYMBOL_STR(strsep) },
	{ 0xd2ad3fae, __VMLINUX_SYMBOL_STR(generic_read_dir) },
	{ 0x999e8297, __VMLINUX_SYMBOL_STR(vfree) },
	{ 0xcd0d1c9, __VMLINUX_SYMBOL_STR(__getblk_gfp) },
	{ 0xd149efd6, __VMLINUX_SYMBOL_STR(unlock_buffer) },
	{ 0x2223df79, __VMLINUX_SYMBOL_STR(blk_get_backing_dev_info) },
	{ 0x853be46d, __VMLINUX_SYMBOL_STR(truncate_setsize) },
	{ 0x81059ce6, __VMLINUX_SYMBOL_STR(from_kgid_munged) },
	{ 0xece784c2, __VMLINUX_SYMBOL_STR(rb_first) },
	{ 0xd07d3274, __VMLINUX_SYMBOL_STR(make_kgid) },
	{ 0xf29db68c, __VMLINUX_SYMBOL_STR(inode_owner_or_capable) },
	{ 0xaa03c585, __VMLINUX_SYMBOL_STR(kmap_atomic) },
	{ 0xaa2b1319, __VMLINUX_SYMBOL_STR(mpage_readpages) },
	{ 0x94775e39, __VMLINUX_SYMBOL_STR(from_kuid) },
	{ 0x917d3d22, __VMLINUX_SYMBOL_STR(mpage_readpage) },
	{ 0x166bd26c, __VMLINUX_SYMBOL_STR(inode_add_bytes) },
	{ 0x7a3188f5, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x46e51a18, __VMLINUX_SYMBOL_STR(__bread_gfp) },
	{ 0x170eba62, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x50eedeb8, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x1250c7e1, __VMLINUX_SYMBOL_STR(_raw_spin_trylock) },
	{ 0xb61e6e17, __VMLINUX_SYMBOL_STR(posix_acl_chmod) },
	{ 0x4e5e2f21, __VMLINUX_SYMBOL_STR(d_obtain_alias) },
	{ 0xb6e41883, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0x7c1372e8, __VMLINUX_SYMBOL_STR(panic) },
	{ 0x6485755e, __VMLINUX_SYMBOL_STR(kunmap) },
	{ 0x2c29bc60, __VMLINUX_SYMBOL_STR(mpage_writepages) },
	{ 0x479c3c86, __VMLINUX_SYMBOL_STR(find_next_zero_bit) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0x4d9b652b, __VMLINUX_SYMBOL_STR(rb_erase) },
	{ 0xb4390f9a, __VMLINUX_SYMBOL_STR(mcount) },
	{ 0x40c6706e, __VMLINUX_SYMBOL_STR(from_kgid) },
	{ 0x6c2e3320, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0x9111e650, __VMLINUX_SYMBOL_STR(kmem_cache_free) },
	{ 0x34caff3, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0x937ade8f, __VMLINUX_SYMBOL_STR(set_nlink) },
	{ 0xe8db8dd2, __VMLINUX_SYMBOL_STR(_raw_write_lock) },
	{ 0xed93f29e, __VMLINUX_SYMBOL_STR(__kunmap_atomic) },
	{ 0xe48def64, __VMLINUX_SYMBOL_STR(setattr_copy) },
	{ 0x5b3b5edd, __VMLINUX_SYMBOL_STR(page_symlink) },
	{ 0x85ff9655, __VMLINUX_SYMBOL_STR(insert_inode_locked) },
	{ 0xae10f9d9, __VMLINUX_SYMBOL_STR(sync_dirty_buffer) },
	{ 0xa735db59, __VMLINUX_SYMBOL_STR(prandom_u32) },
	{ 0xe23f4519, __VMLINUX_SYMBOL_STR(truncate_pagecache) },
	{ 0x5240ee7, __VMLINUX_SYMBOL_STR(percpu_counter_batch) },
	{ 0x4e3567f7, __VMLINUX_SYMBOL_STR(match_int) },
	{ 0x6e0e43d3, __VMLINUX_SYMBOL_STR(unlock_page) },
	{ 0x94710467, __VMLINUX_SYMBOL_STR(generic_file_read_iter) },
	{ 0x388e1c16, __VMLINUX_SYMBOL_STR(up_write) },
	{ 0x68684cf6, __VMLINUX_SYMBOL_STR(down_write) },
	{ 0xc890fcd5, __VMLINUX_SYMBOL_STR(inode_nohighmem) },
	{ 0xa2d04b98, __VMLINUX_SYMBOL_STR(__brelse) },
	{ 0x4caaa84e, __VMLINUX_SYMBOL_STR(nobh_writepage) },
	{ 0x292e56e, __VMLINUX_SYMBOL_STR(inode_init_once) },
	{ 0xc31492ac, __VMLINUX_SYMBOL_STR(bh_submit_read) },
	{ 0xb7585c58, __VMLINUX_SYMBOL_STR(mnt_drop_write_file) },
	{ 0xc6cbbc89, __VMLINUX_SYMBOL_STR(capable) },
	{ 0x5d29c1b7, __VMLINUX_SYMBOL_STR(invalidate_inode_buffers) },
	{ 0x5fb3fc1a, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0xb2fd5ceb, __VMLINUX_SYMBOL_STR(__put_user_4) },
	{ 0x38670693, __VMLINUX_SYMBOL_STR(sync_mapping_buffers) },
	{ 0xf4a5dab2, __VMLINUX_SYMBOL_STR(generic_block_fiemap) },
	{ 0x590fb354, __VMLINUX_SYMBOL_STR(generic_file_mmap) },
	{ 0x132329cc, __VMLINUX_SYMBOL_STR(kmap) },
	{ 0x23c28405, __VMLINUX_SYMBOL_STR(block_write_full_page) },
	{ 0xaa4affae, __VMLINUX_SYMBOL_STR(inode_sub_bytes) },
	{ 0x39e0627e, __VMLINUX_SYMBOL_STR(block_write_end) },
	{ 0xd3323c36, __VMLINUX_SYMBOL_STR(truncate_inode_pages_final) },
	{ 0xd5deacc2, __VMLINUX_SYMBOL_STR(make_kuid) },
	{ 0xf82ec573, __VMLINUX_SYMBOL_STR(rb_prev) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xf6a3b5f5, __VMLINUX_SYMBOL_STR(generic_write_end) },
	{ 0x8865cd67, __VMLINUX_SYMBOL_STR(__breadahead) },
	{ 0x7ab3fff6, __VMLINUX_SYMBOL_STR(unlock_new_inode) },
	{ 0x200c37b, __VMLINUX_SYMBOL_STR(mnt_want_write_file) },
	{ 0x8b8059bd, __VMLINUX_SYMBOL_STR(in_group_p) },
	{ 0x983d4f71, __VMLINUX_SYMBOL_STR(kill_block_super) },
	{ 0x696de5fa, __VMLINUX_SYMBOL_STR(crypto_destroy_tfm) },
	{ 0xb905c66, __VMLINUX_SYMBOL_STR(__percpu_counter_init) },
	{ 0xe8527c, __VMLINUX_SYMBOL_STR(simple_get_link) },
	{ 0x670c7911, __VMLINUX_SYMBOL_STR(inode_change_ok) },
	{ 0xd1088e23, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xe259ae9e, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x462a2e75, __VMLINUX_SYMBOL_STR(match_strlcpy) },
	{ 0x5d9c0d7a, __VMLINUX_SYMBOL_STR(sync_inode_metadata) },
	{ 0xa5526619, __VMLINUX_SYMBOL_STR(rb_insert_color) },
	{ 0x3e6d374c, __VMLINUX_SYMBOL_STR(kmem_cache_create) },
	{ 0x3ccf9b9f, __VMLINUX_SYMBOL_STR(d_tmpfile) },
	{ 0xdfc59855, __VMLINUX_SYMBOL_STR(register_filesystem) },
	{ 0x192a0a68, __VMLINUX_SYMBOL_STR(generic_file_write_iter) },
	{ 0xb1ea2a32, __VMLINUX_SYMBOL_STR(iov_iter_init) },
	{ 0x98a9aa5b, __VMLINUX_SYMBOL_STR(I_BDEV) },
	{ 0x774be59a, __VMLINUX_SYMBOL_STR(iter_file_splice_write) },
	{ 0x9a0c8381, __VMLINUX_SYMBOL_STR(blockdev_superblock) },
	{ 0x5c265cba, __VMLINUX_SYMBOL_STR(sg_init_one) },
	{ 0xb1e2c322, __VMLINUX_SYMBOL_STR(iput) },
	{ 0xca7533fb, __VMLINUX_SYMBOL_STR(read_cache_page) },
	{ 0x89988b29, __VMLINUX_SYMBOL_STR(generic_file_fsync) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x983775a9, __VMLINUX_SYMBOL_STR(inode_dio_wait) },
	{ 0x58582b36, __VMLINUX_SYMBOL_STR(page_get_link) },
	{ 0x1023b155, __VMLINUX_SYMBOL_STR(ihold) },
	{ 0x67081eae, __VMLINUX_SYMBOL_STR(__sb_end_write) },
	{ 0x643e0ce5, __VMLINUX_SYMBOL_STR(call_rcu_sched) },
	{ 0x73931bc3, __VMLINUX_SYMBOL_STR(generic_error_remove_page) },
	{ 0xa1622cf5, __VMLINUX_SYMBOL_STR(d_splice_alias) },
	{ 0xe1f03fbf, __VMLINUX_SYMBOL_STR(sync_filesystem) },
	{ 0x3c8966cc, __VMLINUX_SYMBOL_STR(block_truncate_page) },
	{ 0xa931bbcb, __VMLINUX_SYMBOL_STR(sb_set_blocksize) },
	{ 0x6eb0915, __VMLINUX_SYMBOL_STR(__sb_start_write) },
	{ 0x7a2b0a89, __VMLINUX_SYMBOL_STR(generic_readlink) },
	{ 0x3a9e679a, __VMLINUX_SYMBOL_STR(__bforget) },
	{ 0x9f128f6f, __VMLINUX_SYMBOL_STR(d_make_root) },
	{ 0x8ba360a, __VMLINUX_SYMBOL_STR(__blockdev_direct_IO) },
	{ 0x27a7e3db, __VMLINUX_SYMBOL_STR(inode_needs_sync) },
	{ 0xb74be8b0, __VMLINUX_SYMBOL_STR(__block_write_begin) },
	{ 0xca9360b5, __VMLINUX_SYMBOL_STR(rb_next) },
	{ 0x1ce91b00, __VMLINUX_SYMBOL_STR(mark_buffer_dirty) },
	{ 0x7410f292, __VMLINUX_SYMBOL_STR(unregister_filesystem) },
	{ 0x47ff5fe4, __VMLINUX_SYMBOL_STR(nobh_write_end) },
	{ 0x11f463b4, __VMLINUX_SYMBOL_STR(write_one_page) },
	{ 0xe4de57bb, __VMLINUX_SYMBOL_STR(init_special_inode) },
	{ 0xa51e55f5, __VMLINUX_SYMBOL_STR(new_inode) },
	{ 0x84cfbccf, __VMLINUX_SYMBOL_STR(generic_file_splice_read) },
	{ 0x3d4767e3, __VMLINUX_SYMBOL_STR(generic_fh_to_dentry) },
	{ 0xf1affecd, __VMLINUX_SYMBOL_STR(clear_inode) },
	{ 0xed15b55, __VMLINUX_SYMBOL_STR(d_instantiate) },
	{ 0x690ab86d, __VMLINUX_SYMBOL_STR(nobh_truncate_page) },
	{ 0x8a069c24, __VMLINUX_SYMBOL_STR(__put_page) },
	{ 0x31b9be5e, __VMLINUX_SYMBOL_STR(generic_block_bmap) },
	{ 0xb4c6e6bb, __VMLINUX_SYMBOL_STR(iget_locked) },
	{ 0xb45578b8, __VMLINUX_SYMBOL_STR(memscan) },
	{ 0x215a0f8a, __VMLINUX_SYMBOL_STR(inode_init_owner) },
	{ 0x33edce51, __VMLINUX_SYMBOL_STR(bh_uptodate_or_lock) },
	{ 0xdf929370, __VMLINUX_SYMBOL_STR(fs_overflowgid) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "0AFC5CD555CCB25923E6515");
