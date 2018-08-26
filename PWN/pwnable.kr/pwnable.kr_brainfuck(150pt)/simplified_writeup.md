# brainfuck
## Before Arbitrarily MEMW we should know
- If a pointer is located in .bss/.data segment, it may be abused to falsify any place in computer memory.
- Falsified Global Offset Table can control the flow of a certain program.
- Ret2libc can leak the address of a certain function after the program has been loaded.
## Why that?
- The origin function main has the following combination:
>     memset(&v6, 0, 0x400u);
>     fgets((char *)&v6, 1024, stdin);
- Inspired by most exploit experience, we use the following combination to pwn:
>     gets(&v6);
>     system(v6);
>     #v6->"/bin/sh\0"
- Conseguently, gets -> memset & system -> fgets
- Incidently, a loop while exploiting is a necessary, so we can override 'putchar' or something else used in brainfuck interpreter with 'main'.
## PS:
- At first, I wanna exploit the program by hijacking '__stack_chk_fail', however, the length of v6's buffer is 0x400u while the distance from ebp head to v6 is 0x408u.GG
- Then I pwned like what I said above.