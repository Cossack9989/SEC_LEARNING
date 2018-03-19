# echo1
- `recv()` and `recvuntil()` hurt! That's what I wanna say most.
- Additionally, this pwn challenges is the first challenge with amd64 arch.
## The MOST Important in the Challenge
- equip the rop with `jmp esp` to point to the shellcode in the top of stack, as we cannot always be dying to get the stack address.
- context is indispensible.