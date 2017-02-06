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


## Overflow

Assume that: `char buf[41]` and `int size`

### scanf

* scanf("%s", buf)
    * `%s` doesn't have boundary check.
    * **pwnable**

* scanf("%40s", buf)
    * `%40s`  will only take 40 bytes from input.
    * And it will puts NULL at the end of input.
    * **useless**

* scanf("%41s", buf)
    * At the first sight, it seems reasonable.(seems)
    * It will take 41 bytes from input, but it also puts NULL at the end of input.
    * Therefore, it will have **one-byte-overflow**.
    * **pwnable**

* scanf("%d", size)
    * Special Case: With `alloca(size)`
    * `alloca` allocates memory from stack frame of caller
    * If there will be another function call, make size negative.
    * Then, it will have overlapped stack frame. 
    * Ex: [Seccon CTF quals 2016 cheer_msg](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/cheer-msg-100)

### gets

* gets(buf)
    * No boundary check.
    * **pwnable**

* fgets(buf, 41, stdin)
    * It will take only 40 bytes from input, and put NULL at the the end of input.
    * **useless**

### read

* read(stdin, buf, 41)
    * It will take 41 bytes from input, and it won't put NULL at the end of input.
    * It seems safe, but it may have **information leak**.
    * **leakable**

Example:

**memory layout**
```
0x7fffffffdd00: 0x4141414141414141      0x4141414141414141
0x7fffffffdd10: 0x4141414141414141      0x4141414141414141
0x7fffffffdd20: 0x4141414141414141      0x0000555555554641
```

* If there is a `printf` or `puts` that used to output the buf, it will output until NULL byte.
* In this case, we can get `'A'*41 + '\x46\x55\x55\x55\x55'` instead of just our input `'A'*41`

* fread(stdin, buf, 1, 41)
    * Almost the same as `read`.
    * **leakable**

### strcpy

Assume there is another buffer : `char buf2[60]`

* strcpy(buf, buf2)
    * No boundary check.
    * It will copy the content of buf2(until reaching NULL) which may be longer than buf to buf.
    * Therefore, there may happen overflow.
    * **pwnable**

* strncpy(buf, buf2, 41)
    * It will copy 41 bytes from buf2 to buf, but it won't put NULL at the end.  
    * Since there is no NULL to terminate, it may have **information leak**.
    * **leakable**

### strcat

Assume there is another buffer : `char buf2[60]`

* strcat(buf, buf2)
    * It will put NULL at the end, it may cause **one-byte-overflow**.
    * In some case, we can use this NULL byte to change stack address or heap address.
    * **pwnable**

* strncat(buf, buf2, n)
    * Almost the same as `strcat`.
    * **pwnable**
    * Ex: [Seccon CTF quals 2016 jmper](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/jmper-300)


## Find string in gdb

In problem of [SSP](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf), we need to find out where is the offset of `argv[0]` with input buffer.

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

Need libc base first

### Manually

* `objdump -s libc.so | less` then search 'sh'

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

**preconditions**

* Already leak libc base
* We can leak the content of arbitrary address

There is a symbol `environ` in libc, and it owns stack address.

## Fork problem in gdb

When you use **gdb** debug a binary with `fork()` function, you can use following command to determine which process to follow:

* `set follow-fork-mode parent`
* `set follow-fork-mode child`

**Default will be child**

## Secret of a mysterious section - .tls

If you want to use it, there are several preconditions:

* `malloc` function and you can use it with arbitrary size
* Arbitrary address leaking

We use `malloc` call `mmap` to allocate memory(size 0x21000 is enough). In general, there pages will be placed at the address just before `.tls` section.

There are some useful information on **`.tls`**, such as the address of `main_arena`, `canary` value of stack guard, and a strange `stack address` which points to somewhere on stack but with fixed offset.

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
