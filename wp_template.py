from pwn import *


ld_path = ""
libc_path = ""
p = process([ld_path, ""], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
# p = remote("")

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

