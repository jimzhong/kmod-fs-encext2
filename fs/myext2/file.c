/*
 *  linux/fs/myext2/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  myext2 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 * 	(jj@sunsite.ms.mff.cuni.cz)
 */

#include <linux/time.h>
#include <linux/pagemap.h>
#include <linux/dax.h>
#include <linux/quotaops.h>
#include <linux/vmalloc.h>
#include <linux/uio.h>
#include <linux/string.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include "myext2.h"
#include "acl.h"
#include "myaes.h"

/*
 * Called when filp is released. This happens when all file descriptors
 * for a single struct file are closed. Note that different open() calls
 * for the same file yield different struct file structures.
 */
static int myext2_release_file (struct inode * inode, struct file * filp)
{
	if (filp->f_mode & FMODE_WRITE) {
		mutex_lock(&MYEXT2_I(inode)->truncate_mutex);
		myext2_discard_reservation(inode);
		mutex_unlock(&MYEXT2_I(inode)->truncate_mutex);
	}
	return 0;
}

int myext2_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int ret;
	struct super_block *sb = file->f_mapping->host->i_sb;
	struct address_space *mapping = sb->s_bdev->bd_inode->i_mapping;

	ret = generic_file_fsync(file, start, end, datasync);
	if (ret == -EIO || test_and_clear_bit(AS_EIO, &mapping->flags)) {
		/* We don't really know where the IO error happened... */
		myext2_error(sb, __func__,
			   "detected IO error when writing metadata buffers");
		ret = -EIO;
	}
	return ret;
}

/* Copied from read_write.c */

static ssize_t new_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
        struct iovec iov = { .iov_base = buf, .iov_len = len };
        struct kiocb kiocb;
        struct iov_iter iter;
        ssize_t ret;

        init_sync_kiocb(&kiocb, filp);
        kiocb.ki_pos = *ppos;
        iov_iter_init(&iter, READ, &iov, 1, len);

        ret = generic_file_read_iter(&kiocb, &iter);
        BUG_ON(ret == -EIOCBQUEUED);
        *ppos = kiocb.ki_pos;
        return ret;
}

static ssize_t new_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
        struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };
        struct kiocb kiocb;
        struct iov_iter iter;
        ssize_t ret;

        init_sync_kiocb(&kiocb, filp);
        kiocb.ki_pos = *ppos;
        iov_iter_init(&iter, WRITE, &iov, 1, len);

        ret = generic_file_write_iter(&kiocb, &iter);
        BUG_ON(ret == -EIOCBQUEUED);
        if (ret > 0)
                *ppos = kiocb.ki_pos;
        return ret;
}

/* Code below is modified */

//static unsigned char AES_KEY[AES_KEY_SIZE] = "12345678ABCDEFGH";

static ssize_t myext2_write_crypt(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
    int i;
    int offset;
    char *encbuf;
    char *old_encbuf;
    size_t old_len = len;
    ssize_t ret;
    //cipher related vars
    struct crypto_skcipher *tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    SKCIPHER_REQUEST_ON_STACK(req, tfm);
    struct scatterlist src, dest;
    unsigned long counter[4];
    unsigned char otp[AES_BLOCK_SIZE];
    struct inode *inode = filp->f_inode;
    struct myext2_inode_info *ei = MYEXT2_I(inode);
    struct myext2_sb_info *sbi= inode->i_sb->s_fs_info;

    counter[0] = ei->i_nonce[0];
    counter[1] = ei->i_nonce[1];
    counter[2] = 0x00;
    
    sg_init_one(&src, counter, sizeof(counter));
    sg_init_one(&dest, otp, sizeof(otp));

    printk("Encrypting %d bytes, ppos=%lld, nonce=%lx%lx\n", len, *ppos, counter[0], counter[1]);

    if(IS_ERR(tfm))
    {
        printk("Error allocating cipher\n");
        return PTR_ERR(tfm);
    }
    if(crypto_skcipher_setkey(tfm, sbi->s_aes_key, AES_KEY_SIZE) != 0)
    {
        printk("Error setkey\n");
        ret = -ENOMEM;
        goto write_cleanup;
    }
    skcipher_request_set_tfm(req, tfm);
    skcipher_request_set_crypt(req, &src, &dest, sizeof(counter), NULL);
    
    old_encbuf = encbuf = vmalloc(len);
    if (unlikely(encbuf == NULL))
    {
        printk("Vmalloc failed\n");
        ret = -ENOMEM;
        goto write_cleanup;
    }

    // encrypt the first block if it is not align
    offset = (*ppos) % AES_BLOCK_SIZE;
    if (offset > 0)
    {
        counter[3] = (unsigned long)((*ppos) >> AES_BLOCK_SIZE_SHIFT);
        printk("first counter = %lx\n", counter[3]);
        crypto_skcipher_encrypt(req);
        for (i = 0; i < len && (i + offset) < AES_BLOCK_SIZE; i++)
        {
            *encbuf++ = otp[i+offset] ^ *buf++;
        }
        len -= i;
    }
    else
    {
        counter[3] = ((*ppos) >> AES_BLOCK_SIZE_SHIFT) - 1;    //because ++ below
    }
    // encrypt following aligned fully blocks
    while (len >= AES_BLOCK_SIZE)
    {
        counter[3]++;
        //printk("full counter = %lx\n", counter[3]);
        crypto_skcipher_encrypt(req);
        for (i = 0; i < AES_BLOCK_SIZE; i++)
        {
            *encbuf++ = otp[i] ^ *buf++;
        }
        len -= AES_BLOCK_SIZE;
    }
    //handle the last block if it is partial
    if (len > 0)
    {
        counter[3] ++;
        printk("last counter = %lx\n", counter[3]);
        crypto_skcipher_encrypt(req);
        for (i = 0; i < len; i++)
        {
            *encbuf++ = otp[i] ^ *buf++;
        }
    }
    
    printk("Encrypted\n");
    ret = new_sync_write(filp, old_encbuf, old_len, ppos);    
    printk("Write Retval = %d\n", ret);
    vfree(old_encbuf);

write_cleanup:
    crypto_free_skcipher(tfm);
    return ret;
}


static ssize_t myext2_read_crypt(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    int i;
    int offset;
    loff_t old_ppos = *ppos;
    ssize_t ret;
    
    //cipher related vars
    struct crypto_skcipher *tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    SKCIPHER_REQUEST_ON_STACK(req, tfm);
    struct scatterlist src, dest;
    unsigned long counter[4];
    unsigned char otp[AES_BLOCK_SIZE];
    struct inode *inode = filp->f_inode;
    struct myext2_sb_info *sbi= inode->i_sb->s_fs_info;
    struct myext2_inode_info *ei = MYEXT2_I(inode);
        
    counter[0] = ei->i_nonce[0];
    counter[1] = ei->i_nonce[1];
    counter[2] = 0x00;
    
    sg_init_one(&src, counter, sizeof(counter));
    sg_init_one(&dest, otp, sizeof(otp));
    
    if(IS_ERR(tfm))
    {
        printk("Error allocating cipher\n");
        return PTR_ERR(tfm);
    }
    if(crypto_skcipher_setkey(tfm, sbi->s_aes_key, AES_KEY_SIZE) != 0)
    {
        printk("Error setkey\n");
        ret = -ENOMEM;
        goto read_cleanup;
    }
    
    skcipher_request_set_tfm(req, tfm);
    skcipher_request_set_crypt(req, &src, &dest, sizeof(counter), NULL);
    
    ret = len = new_sync_read(filp, buf, len, ppos);
    printk("Decrypting %d bytes, ppos=%lld, nonce=%lx%lx\n", len, *ppos, counter[0], counter[1]);
    if (ret == 0)
        goto read_cleanup;
    
    // decrypt the first block if it is not align
    offset = (old_ppos) % AES_BLOCK_SIZE;
    if (offset > 0)
    {
        counter[3] = (unsigned long)((old_ppos) >> AES_BLOCK_SIZE_SHIFT);
        printk("first counter = %lx\n", counter[3]);
        crypto_skcipher_encrypt(req);
        for (i = 0; i < len && (i + offset) < AES_BLOCK_SIZE; i++)
        {
            *buf++ ^= otp[i+offset];
        }
        len -= i;
    }
    else
    {
        counter[3] = (unsigned long)((old_ppos) >> AES_BLOCK_SIZE_SHIFT) - 1;    //because ++ below
    }
    // decrypt following aligned fully blocks
    while (len >= AES_BLOCK_SIZE)
    {
        counter[3]++;
        //printk("full counter = %lx\n", counter[3]);
        crypto_skcipher_encrypt(req);
        for (i = 0; i < AES_BLOCK_SIZE; i++)
        {
            *buf++ ^= otp[i];
        }
        len -= AES_BLOCK_SIZE;
    }
    //handle the last block if it is partial
    if (len > 0)
    {
        counter[3] ++;
        printk("last counter = %lx\n", counter[3]);
        crypto_skcipher_encrypt(req);
        for (i = 0; i < len; i++)
        {
            *buf++ ^= otp[i];
        }
    }
    
    printk("Decrypted\n");
    
read_cleanup:
    crypto_free_skcipher(tfm);
    
    return ret;
}

/*
 * We have mostly NULL's here: the current defaults are ok for
 * the myext2 filesystem.
 */
const struct file_operations myext2_file_operations = {
    .read       = myext2_read_crypt,
    .write      = myext2_write_crypt,
	.llseek		= generic_file_llseek,
//	.read_iter	= generic_file_read_iter,
//	.write_iter	= generic_file_write_iter,
	.unlocked_ioctl = myext2_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= myext2_compat_ioctl,
#endif
	.mmap		= generic_file_mmap,
	.open		= dquot_file_open,
	.release	= myext2_release_file,
	.fsync		= myext2_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
};

const struct inode_operations myext2_file_inode_operations = {
#ifdef CONFIG_MYEXT2_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= myext2_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.setattr	= myext2_setattr,
	.get_acl	= myext2_get_acl,
	.set_acl	= myext2_set_acl,
	.fiemap		= myext2_fiemap,
};
