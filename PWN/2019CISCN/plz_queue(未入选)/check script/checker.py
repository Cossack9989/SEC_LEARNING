import sys
from pwn import *
host = sys.argv[1]
port = int(sys.argv[2])
timeout = 30

#except return Correct/Error info, not return another info
context.log_level = 'critical'

def getIO():
    return remote(host, port, timeout=timeout)


def check1():
    try:
        global io
        io = getIO()
        
        io.recvuntil("QUEUE SIZE : ")
        io.sendline("3")
        io.recvuntil(">> ")
        io.sendline("1")

        io.recvuntil("MSG SIZE : ")
        io.sendline("8")
    
        io.send("mozhucy")

        io.recvuntil("mozhucy")
        if io.recv(1) == "\n":
            return False
        return True
    except:
        return False

    
def check2():
    try:
        global io
        io = getIO()
        io.recvuntil("QUEUE SIZE : ")
        io.sendline("3")
        io.recvuntil(">> ")
        io.sendline("1")

        io.recvuntil("MSG SIZE : ")
        io.sendline("8")

        io.send("m.%p.")

        io.recvuntil("m.")
        buf = io.recvline().split(".")[0]
        if int(buf,16) == u64(buf[2:].decode("hex").rjust(8,"\x00")[::-1]):
            return True
        else:
            return False
    except:
        return False

def proof(io,chk=p64(0)):
    io.sendlineafter(">> ","3")
    ret = io.recvuntil(' ')[:-1]
    io.sendafter("check:",chk)
    return ret
def check3():
    try:
        global io
        io = getIO()
        tmp = []
        for i in range(1,100):
            tmp.append(proof(io))
            if(i>=2):
                print tmp[i],i
                if(tmp[i]==tmp[i-1]):
                    return False
        return True
    except:
        return False

def checker():
    try:
        if check1() and check2() :#and check3():
            return (True, "IP: "+host+" OK")
    except Exception as e:
        return (False, "IP: "+host+" is down, "+str(e))

if __name__ == '__main__':
    print(checker())
