```
root@MiWiFi-R3-srv:~/Desktop/Reverse# nc 47.98.118.58 9999SUS>> print dir()
['__builtins__', '__doc__', '__file__', '__name__', '__package__', 'builtins_clear', 'cmd', 'delete_type', 'get_dict', 'hack', 'inp', 'input_filter']
SUS>> hack(1111)
Guess error
SUS>> hack('flag')
Guess error
SUS>> print hack.__code__ 
<code object hack at 0x7f65aac82430, file "/home/ctf/sandbox.py", line 32>
SUS>> print hack.__code__.co_consts
(None, '02d210cb93c99343245780ac32c124ac', '5c72a1d444cf3121a5d25f2db4147ebb', 'Guess error')
SUS>> print hack.__code__.co_names   
('file', 'read')
SUS>> print hack('02d210cb93c99343245780ac32c124ac')
02d210cb93c99343245780ac32c124ac has been banned!
SUS>> print hack('02d210cb93c99343245780ac32c124a'+'c')
SUSCTF{ca21c15bbfc6278764fd07955dd3dbf1}

None
SUS>> 
```