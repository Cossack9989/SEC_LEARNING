# level4
## checksec
>     Arch:     i386-32-little
>     RELRO:    Partial RELRO
>     Stack:    No canary found
>     NX:       NX enabled
>     PIE:      No PIE (0x8048000)
## exp_logic
- Use DynELF to leak the true address of some certain symbols after loading.
- Write '/bin/sh' into .bss segment or .data segment
## exp_script
detailed script can be found in level4.py
or you can click this link as the access to the whole writeup.[Click here](http://blog.csdn.net/cossack9989/article/details/79330358)
 