CTF-pwn-tips
===========================


# Catalog
* [Overflow](#overflow)
* [Find string in gdb](#find-string-in-gdb)
* [Binary Service](#binary-service)
* [Find specific function offset in libc](#find-specific-function-offset-in-libc)
* [Find '/bin/sh' or 'sh' in library](#find-binsh-or-sh-in-library)
* [Leak stack address](#leak-stack-address)
* [Fork problem in gdb](#fork-problem-in-gdb)
* [Secret of a mysterious section - .tls](#secret-of-a-mysterious-section---tls)
* [Predictable RNG(Random Number Generator)](#predictable-rngrandom-number-generator)
* [Make stack executable](#make-stack-executable)
* [Use one-gadget-RCE instead of system](#use-one-gadget-rce-instead-of-system)
* [Hijack hook function](#hijack-hook-function)


## Overflow

Assume that: `char buf[41]` and `int size`

### scanf

* `scanf("%s", buf)`
    * `%s` doesn't have boundary check.
    * **pwnable**

* `scanf("%40s", buf)`
    * `%40s`  will only take 40 bytes from input.
    * And it will puts NULL at the end of input.
    * **useless**

* `scanf("%41s", buf)`
    * At the first sight, it seems reasonable.(seems)
    * It will take **41 bytes** from input, but it also **puts NULL at the end of input.**
    * Therefore, it will have **one-byte-overflow**.
    * **pwnable**

* `scanf("%d", size)`
    * **constraints:**
        * Used with `alloca(size)`
        * There is a function call after calling `alloca`
    * Since `alloca` allocates memory from the stack frame of caller, there is an instruction `sub esp, eax` to achieve that.
    * If we make size negative, it will have overlapped stack frame. 
    * Ex: [Seccon CTF quals 2016 cheer_msg](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/cheer-msg-100)

### gets

* `gets(buf)`
    * No boundary check.
    * **pwnable**

* `fgets(buf, 41, stdin)`
    * It will take only **40 bytes** from input, and put NULL at the the end of input.
    * **useless**

### read

Here we let buf to be size of 40

* `read(stdin, buf, 40)`
    * It will take **40 bytes from** input, and it won't put NULL at the end of input.
    * It seems safe, but it may have **information leak**.
    * **leakable**

Example:

**memory layout**
```
0x7fffffffdd00: 0x4141414141414141      0x4141414141414141
0x7fffffffdd10: 0x4141414141414141      0x4141414141414141
0x7fffffffdd20: 0x4141414141414141      0x00007fffffffe1cd
```

* If there is a `printf` or `puts` which is used to output the buf, it will output until reaching NULL byte.
* In this case, we can get `'A'*40 + '\xcd\xe1\xff\xff\xff\x7f'` instead of just our input `'A'*40`

* `fread(stdin, buf, 1, 40)`
    * Almost the same as `read`.
    * **leakable**

### strcpy

Assume there is another buffer : `char buf2[60]`

* `strcpy(buf, buf2)`
    * No boundary check.
    * It will copy the content of buf2(until reaching NULL byte) which may be longer than `length(buf)` to buf.
    * Therefore, it may happen overflow.
    * **pwnable**

* `strncpy(buf, buf2, 41)`
    * It will copy 41 bytes from buf2 to buf, but it won't put NULL at the end.  
    * Since there is no NULL byte to terminate, it may have **information leak**.
    * **leakable**

### strcat

Assume there is another buffer : `char buf2[60]`

* `strcat(buf, buf2)`
    * Of course, it may cause **overflow** if `length(buf)` isn't large enough.
    * It will put NULL at the end, it may cause **one-byte-overflow**.
    * In some case, we can use this NULL byte to change stack address or heap address.
    * **pwnable**

* `strncat(buf, buf2, n)`
    * Almost the same as `strcat`, but with size limitation.
    * **pwnable**
    * Ex: [Seccon CTF quals 2016 jmper](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/jmper-300)


## Find string in gdb

In the problem of [SSP](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf), we need to find out the offset between `argv[0]` and input buffer.

### Normal gdb

* Use `p/x ((char **)environ)` in gdb, and the address of argv[0] will be the output - 0x10

Ex:

```
(gdb) p/x (char **)environ
$9 = 0x7fffffffde38
(gdb) x/gx 0x7fffffffde38-0x10
0x7fffffffde28: 0x00007fffffffe1cd
(gdb) x/s 0x00007fffffffe1cd
0x7fffffffe1cd: "/home/naetw/CTF/seccon2016/check/checker"
```

### [gdb peda](https://github.com/longld/peda)

* Use `searchmem "/home/naetw/CTF/seccon2016/check/checker"`
* Then use `searchmem $result_address`

```
gdb-peda$ searchmem "/home/naetw/CTF/seccon2016/check/checker"
Searching for '/home/naetw/CTF/seccon2016/check/checker' in: None ranges
Found 3 results, display max 3 items:
[stack] : 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffed7c ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffefcf ("/home/naetw/CTF/seccon2016/check/checker")
gdb-peda$ searchmem 0x7fffffffe1cd
Searching for '0x7fffffffe1cd' in: None ranges
Found 2 results, display max 2 items:
   libc : 0x7ffff7dd33b8 --> 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffde28 --> 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
```

## Binary Service

Normal:

* `ncat -vc ./binary -kl 127.0.0.1 $port`

With specific library in two ways:

* `ncat -vc 'LD_PRELOAD=/path/to/libc.so ./binary' -kl 127.0.0.1 $port`
* `ncat -vc 'LD_LIBRARY_PATH=/path/of/libc.so ./binary' -kl 127.0.0.1 $port`

After this, you can connect to binary service by command `nc localhost 4000`(I use port number 4000 here.)

## Find specific function offset in libc

If we leaked libc address of certain function successfully, we could use it minus offset of that function, then we can get libc base address of this time.

### Manually

* `readelf -s $libc | grep ${function}@`

Ex:

```
$ readelf -s libc-2.19.so | grep system@
    620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
   1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
```

### Automatically

* Use [pwntools](https://github.com/Gallopsled/pwntools)
* Then you can use it in your exploit.

Ex:

```python
from pwn import *

libc = ELF('libc.so')
system_off = libc.symbols['system']
```

## Find '/bin/sh' or 'sh' in library

Need libc base address first

### Manually

* `objdump -s libc.so | less` then search 'sh'
* `strings -tx libc.so | grep /bin/sh`

### Automatically

* Use [pwntools](https://github.com/Gallopsled/pwntools)

Ex:

```python
from pwn import *

libc = ELF('libc.so')
...
sh = base + next(libc.search('sh\x00'))
binsh = base + next(libc.search('/bin/sh\x00'))
```

## Leak stack address

* Already leak libc base address
* Can leak the content of arbitrary address

There is a symbol `environ` in libc, whose value is the same as the third argument of `main` function, `char **envp` .  
The value of `char **envp` is on the stack, thus we can leak stack address with this symbol.

```
(gdb) list 1
1       #include <stdlib.h>
2       #include <stdio.h>
3
4       extern char **environ;
5
6       int main(int argc, char **argv, char **envp)
7       {
8           return 0;
9       }
(gdb) x/gx 0x7ffff7a0e000 + 0x3c5f38
0x7ffff7dd3f38 <environ>:       0x00007fffffffe230
(gdb) p/x (char **)envp
$12 = 0x7fffffffe230
```

* `0x7ffff7a0e000` is current libc base address
* `0x3c5f38` is offset of `environ` in libc

This [manual](https://www.gnu.org/software/libc/manual/html_node/Program-Arguments.html) explains details about `environ`.

## Fork problem in gdb

When you use **gdb** to debug a binary with `fork()` function, you can use following command to determine which process to follow (default is child):

* `set follow-fork-mode parent`
* `set follow-fork-mode child`

## Secret of a mysterious section - .tls

* Need `malloc` function and you can malloc with arbitrary size
* Arbitrary address leaking

We make `malloc` use `mmap` to allocate memory(size 0x21000 is enough). In general, these pages will be placed at the address just before `.tls` section.

There are some useful information on **`.tls`**, such as the address of `main_arena`, `canary` (value of stack guard), and a strange `stack address` which points to somewhere on stack but with fixed offset.

**Before call mmap:**

```
7fecbfe4d000-7fecbfe51000 r--p 001bd000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe51000-7fecbfe53000 rw-p 001c1000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe53000-7fecbfe57000 rw-p 00000000 00:00 0
7fecbfe57000-7fecbfe7c000 r-xp 00000000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc0068000-7fecc006a000 rw-p 00000000 00:00 0              <- .tls section
7fecc0078000-7fecc007b000 rw-p 00000000 00:00 0
7fecc007b000-7fecc007c000 r--p 00024000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc007c000-7fecc007d000 rw-p 00025000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
```

**After call mmap:**

```
7fecbfe4d000-7fecbfe51000 r--p 001bd000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe51000-7fecbfe53000 rw-p 001c1000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe53000-7fecbfe57000 rw-p 00000000 00:00 0
7fecbfe57000-7fecbfe7c000 r-xp 00000000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc0045000-7fecc006a000 rw-p 00000000 00:00 0              <- memory of mmap + .tls section
7fecc0078000-7fecc007b000 rw-p 00000000 00:00 0
7fecc007b000-7fecc007c000 r--p 00024000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc007c000-7fecc007d000 rw-p 00025000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
```

## Predictable RNG(Random Number Generator)

When the binary uses the RNG to make the address of important information or sth, we can guess the same value if it's predictable.

Assuming that it's predictable, we can use [ctypes](https://docs.python.org/2/library/ctypes.html) which is a build-in module in Python.

**ctypes** allows calling function in DLL(Dynamic-Link Library) or Shared Library.

Therefore, if binary has an init_proc like this:

```c
srand(time(NULL));
while(addr <= 0x10000){
    addr = rand() & 0xfffff000;
}	
secret = mmap(addr,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,-1,0);
if(secret == -1){
    puts("mmap error");
    exit(0);
}
```

Then we can use **ctypes** to get the same value of addr.

```python
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/path/to/dll')
LIBC.srand(LIBC.time(0))
addr = LIBC.rand() & 0xfffff000
```

## Make stack executable

* [link1](http://radare.today/posts/defeating-baby_rop-with-radare2/)
* [link2](https://sploitfun.wordpress.com/author/sploitfun/)
* Haven't read yet orz

## Use one-gadget-RCE instead of system

* Have libc base address
* Write to arbitrary address

Almost every pwnable challenge needs to call `system('/bin/sh')` in the end of exploit, but if we want to call that, we have to manipulate the parameters and, of course, hijacking some function to `system`. What if we **can't** manipulate the parameter? 

Use [one-gadget-RCE](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf)!

With **one-gadget-RCE**, we can just hijack `.got.plt` to make program jump to **one-gadget**, but there are some constraints needed to be satisfied before use it.

There are lots of **one-gadgets** in libc. Each one needs different constraints but those are similar. Each constraint is about registers' state.

Ex:

* ebx is the address of `rw-p` area of libc
* [esp+0x34] == NULL

How can we get these constraints? Here is an useful tool [one_gadget](https://github.com/david942j/one_gadget) !!!!

Therefore, if we can satisfy those constraints, we can get the shell more easily.

## Hijack hook function

* Have libc base address
* Write to arbitrary address
* The program uses `malloc`, `free` or `realloc`.

By manual:

> The GNU C Library lets you modify the behavior of `malloc`, `realloc`, and `free` by specifying appropriate hook functions. You can use these hooks to help you debug programs that use dynamic memory allocation, for example.

There are hook variables declared in malloc.h, and their default value would be `0x0`.

* `__malloc_hook`
* `__free_hook`
* ...

Since they are used to help us debug programs, they are writable during the execution.

```
0xf77228e0 <__free_hook>:       0x00000000
0xf7722000 0xf7727000 rw-p      mapped
```

Let's look into the [src](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#2917) of malloc.c. I will use `__libc_free` to demo.

```c
void (*hook) (void *, const void *) = atomic_forced_read (__free_hook);
if (__builtin_expect (hook != NULL, 0))
{
    (*hook)(mem, RETURN_ADDRESS (0));
    return;
}
```

It will check the value of `__free_hook`. If it's not NULL, it would call the hook function first. Here, we would like to use **one-gadget-RCE**. Since hook function call is in the libc, the constraint of **one-gadget** is usually satisfied.
