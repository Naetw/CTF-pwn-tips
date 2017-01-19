# CTF-pwn-tips-I-have-learned

## Overflow

Assume that: `char buf[41]` and `int size`

#### scanf

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

#### gets

* gets(buf)
    * No boundary check.
    * **pwnable**

* fgets(buf, 41, stdin)
    * It will take only 40 bytes from input, and put NULL at the the end of input.
    * **useless**

#### read

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
* In this case, we can get `'A'*41 + '\x46\x55\x55\x55\x55'`

* fread(stdin, buf, 1, 41)
    * Almost the same as `read`.
    * **leakable**

#### strcpy

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

#### strcat

Assume there is another buffer : `char buf2[60]`

* strcat(buf, buf2)
    * It will put NULL at the end, it may cause **one-byte-overflow**.
    * In some case, we can use this NULL byte to change stack address or heap address.
    * **pwnable**

* strncat(buf, buf2, n)
    * Almost the same as `strcat`.
    * **pwnable**
    * Ex: [Seccon CTF quals 2016 jmper](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/jmper-300)
