# Classical Format String Vulnerability PWN-200
## EXPmethod1
### leak canary
gdb-peda will help you get it
### exploit logic
```
  v6 = *MK_FP(__GS__, 20);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  gets((char *)&v5);
  printf((const char *)&v5);
  gets((char *)&v5);
  result = 0;
  v4 = *MK_FP(__GS__, 20) ^ v6;
  return result;
```
- first gets and printf can be used to leak canary
- second gets should be used to overflow the stack and lead the flow to canary_protect_me
## EXPmethod2
**waiting**