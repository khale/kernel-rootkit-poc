# The b4rnd00r kernel rootkit
[![Build Status](https://travis-ci.com/khale/kernel-rootkit-poc.svg?token=576AGsdiqBgiBzCbaoJT&branch=master)](https://travis-ci.com/khale/kernel-rootkit-poc)

This is proof-of-concept (PoC) of a kernel-resident rootkit. While it is probably not as
advanced as something you might find in the wild, it is realistic both in its
aim and methods. It is closely tied to another PoC that injects a running process
via PLT/GOT poisoning (see [here](https://github.com/khale/elf-hijack)). 

b4rnd00r only works with Linux, and has been tested on systems as new as
kernel version 4.8. It for sure does not work with 5.x kernels due in part
to its rather noisy bit banging on CR0. 

b4rnd00r currently performs the following actions:

- Hides a malicious library, resident due to code injection (both from `/proc/<pid>/maps` and on the filesystem)
- Hides _itself_ from the filesystem and from `/proc/modules` (and thus `lsmod`)
- Implements a local backdoor by exposing a character device that provides an interface for the module. When the user writes a specific string to this character device file, that user becomes root.

## How it Works

At its core, a kernel rootkit is so effective because
of its (close to) total control of what is exposed
to userspace. Thus, if it can be subverted, information
presented to the user (and the operation of the kernel
itself) can be manipulated. That is exactly what is done here.

### File Hiding
When you run a command like `ls` or `find`, at some point
those commands need to get a listing of files in a directory.
On Linux, this is information is exposed (via the file
system) using the `getdents()` system call.  In theory, if we
can intercept this system call before its results are
returned to the user program, we can scrub the results, thus
cloaking any file we'd like (including malicious libraries,
our rootkit files, etc.).

### Kernel Backdoor
A backdoor is just a shortcut to gaining access that would
normally be restricted (e.g. root privileges).  If you've got
control of the kernel, this is pretty easy to do, since the
kernel is ultimately the arbiter of user and group IDs. This
rootkit creates a device file at `/dev/b4rn` which expects
input from a user. If the _right_ input is written to this
file, the kernel will change the writing process's ID set
(uid, euid, gid, egid) to 0, thus granting root. 


### Interposing on `/proc/modules`
The kernel exposes which kernel modules (e.g. drivers) have been loaded into
the kernel (and their attributes) via a proc file (`/proc/modules`). To
manipulate the user-visible output of this file (to hide b4rnd00r itself), we
need to intercept the kernel's handler function which produces this output and
modify what it produces. To do this, we find this handler function, and replace
it with our own.

### Interposing on `/proc/<pid>/maps`
The idea here is the same as above, but instead of hiding the module, we scrub
the kernel's address space map to cloak malicious shared libraries loaded into
programs' address spaces. This turns out to be a little more involved than
previous steps because of this proc file's usage of the kernel's `seq_file`
interface (see [here](https://www.kernel.org/doc/Documentation/filesystems/seq_file.txt)).

### Defeating Countermeasures
For a while now, the Linux kernel has started to be more careful when
exposing capabilities to externally loaded (module) code. For example:

- Modules not digitally signed by a trusted entity will "taint" the kernel (see [here](https://www.kernel.org/doc/html/v4.15/admin-guide/module-signing.html),
  leaving an audit trail. There are ways to get around this, but it raises the barrier.

- Most symbols in the kernel are not exported to loadable kernel modules, so
  they cannot be referenced directly. This makes it harder to do a number of
  things. However, we can still find them by using the `kallsyms`
  interface in the kernel or by parsing the `System.map` file for the system's kernel
  (usually sitting in `/boot/System.map.<your-kernel-version>`). b4rnd00r does just this.

- After the kernel boots the system, most pages will be marked read-only (even by the kernel)
  to prevent modules from writing to them. We can still get around this (because we're in kernel
  space) but its an annoyance. b4rnd00r gets around it by disabling the processor's write protection
  capability (by flipping a bit in the `cr0` control register), which causes write protected
  page table entries to be ignored.

Newer kernels will go even further (for example revoking access to `/dev/mem` even for root, 
being very paranoid about control registers changing, etc.) to prevent such attacks. This
rootkit will actually fail to load on the newest of kernels.

## Ideas to Extend
- Add a keylogger
- Hide network socket (e.g. from a bind shell or active reverse shells)
- Hide specific processes (or threads) (so they don't appear in `ps` and `/proc/<pid>/`
- Trigger further code injection
- Provide interactivity (e.g. a command interpreter setting on the device file)

## Usage

Here's an example on the SEED Ubuntu 16.04 VM:

```
$ make
$ ls
b4rnd00r.c b4rnd00r.ko libtest.so.1.0 Makefile modules.order Module.symvers README.md
$ sudo insmod ./b4rnd00r.ko
$ ls
Makefile modules.order Module.symvers README.md
$ whoami
seed
$ ls /dev | grep b4rn
$ echo "hello" > /dev/b4rn
$ whoami
seed
$ echo "JOSHUA" > /dev/b4rn
$ whoami
root

```
