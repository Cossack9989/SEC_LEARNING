from pwn import *
context.arch = 'amd64'
f = open("shellcode.txt","wb")
src = [  0x5A, 0x5A, 0x4A, 0x20, 0x6C, 0x6F, 0x76, 0x65, 0x73, 0x20, 
  0x73, 0x68, 0x65, 0x6C, 0x6C, 0x5F, 0x63, 0x6F, 0x64, 0x65, 
  0x2C, 0x61, 0x6E, 0x64, 0x20, 0x68, 0x65, 0x72, 0x65, 0x20, 
  0x69, 0x73, 0x20, 0x61, 0x20, 0x67, 0x69, 0x66, 0x74, 0x3A, 
  0x0F, 0x05, 0x20, 0x65, 0x6E, 0x6A, 0x6F, 0x79, 0x20, 0x69, 
  0x74, 0x21, 0x0A]
data = ''
for i in range(len(src)):
	for j in range(5):
		print i,j
		try:
			strr = ''
			for k in src[i:i+j]:
				strr += chr(k)
			tmp = str(disasm(strr))
			print tmp
			data += tmp+'\n\n'
		except:
			continue
f.write(data)
f.close()