##### 关于exp-fdup
- 新的利用方式 劫持`__malloc_hook`为`realloc`+0x14，劫持`__realloc_hook`为onegadget
- 注意realloc函数开头代码
```
.text:0000000000083B10                 push    r15             ; Alternative name is '__libc_realloc'
.text:0000000000083B12                 push    r14
.text:0000000000083B14                 push    r13
.text:0000000000083B16                 push    r12
.text:0000000000083B18                 mov     r13, rsi
.text:0000000000083B1B                 push    rbp
.text:0000000000083B1C                 push    rbx
.text:0000000000083B1D                 mov     rbx, rdi
.text:0000000000083B20                 sub     rsp, 38h
.text:0000000000083B24                 mov     rax, cs:__realloc_hook_ptr
.text:0000000000083B2B                 mov     rax, [rax]
.text:0000000000083B2E                 test    rax, rax
.text:0000000000083B31                 jnz     loc_83D38
```
```
.text:0000000000083D38 loc_83D38:                              ; CODE XREF: realloc+21↑j
.text:0000000000083D38                 mov     rdx, [rsp+68h]
.text:0000000000083D3D                 call    rax
.text:0000000000083D3F                 mov     rbp, rax
.text:0000000000083D42                 jmp     loc_83BCE
```
若因为栈上变量非0，可考虑劫持地址修正为`__realloc`+0x10，多执行一次`sub rsp,38h`
##### 关于exp-pretime
- under way