from base64 import b64encode
s = "\x15\x55\xd3\x0f\x38\xb0\xdb\xca\xec\x83\xc0\xf9"
#s = s[::-1]
t = b64encode(s)
t1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
t2 = "ABCyVPGHTJKLMNOFQRSIUEWDYZgbc8sfah1jklmnopqret5v0xX9wi234u67dz+/"
flag = ''
for j in t:
	attach_byte = j
	for i in range(len(t1)):
		if t1[i] == j:
			attach_byte = t2[i]
	flag += attach_byte
print flag