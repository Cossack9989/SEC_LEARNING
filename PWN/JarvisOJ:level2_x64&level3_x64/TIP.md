# Registers of x86-64 and the method of transferring parameters
- While transferring parameters, the first six parameters will be stored in registers in the following order:`>rdi>rsi>rdx>rcx>r8>r9` 
- Then the rest of parameters will be stored in stack.
- Consequently the structure of ROP looks like the following pattern:
```
+---------+------------------+-----------+---------+---------------------+--------
| padding | pop_register;ret | parameter | ... ... | address_of_function | ... ...
+---------+------------------+-----------+---------+---------------------+--------
```