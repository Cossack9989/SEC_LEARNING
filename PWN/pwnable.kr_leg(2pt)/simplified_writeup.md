# leg
## Learn ARM first
### knowledges which will be used in this challenge:
- A certain function's returned value is stored in R0 register
- While BX makes R[0]=0, thumb -> ARM; and while BX makes R[0]=1, ARM -> thumb. [Click here to know more](https://www.cnblogs.com/yygsj/p/5428500.html)
- Assuming programs run in pipeline: while instructions in ARM mode, PC(R15)=PC+8; and while instructions in thumb mode, PC=PC+4
- What is PC/LR/SP? [Click here to know more](http://blog.csdn.net/aguangg_6655_la/article/details/53613270)
## Then just calculate and pwn