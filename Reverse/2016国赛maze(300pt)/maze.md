title: cis2016-re300-maze
categories:
- 二进制
---

# 初探maze #
- 又遇到了maze,难度比bugku的take the maze简单一点,但是比nctf和nust的maze要复杂好多.
- 运行发现,传参形式为命令行.错误会报错play again!
- IDA打开,查看主函数,很简短

```c
int __cdecl main(int argc, const char **input, const char **envp)
{
  if ( argc != 2 )
  {
    memset(byte_13C0AA8, -1, 484u);
    sub_13B10B0();
    sub_13B1000();
    if ( sub_13B1150(input[1]) )
    {
      sub_13B1290((void *)input[1]);
      return 0;
    }
    printf("play again!");
  }
  return 0;
}
```

- 大概意思就是检测输入是否为空,非空则进入判断,首先memset一个484的内存空间,紧接着的两个函数对byte_13C0AA8操作.

查看sub_13B1290验证函数,函数具体如下图.
```c
int __cdecl sub_401150(const char *input)
{
  const char *input_1; // edx@1
  int result; // eax@2
  char v3; // al@3
  int v4; // ebx@3
  int Y; // ecx@3
  int X; // esi@3
  signed int v7; // edi@3
  int v8; // ebp@4
  unsigned int v9; // edx@7
  signed int v10; // ebx@8
  signed int v11; // eax@11
  int v12; // [sp+4h] [bp-4h]@3

  input_1 = input;
  if ( strlen(input) & 1 )                      // 奇数
    return 0;
  v3 = *input;
  v4 = 0;
  Y = 0;
  X = 0;
  v7 = -1;
  v12 = 0;
  if ( !*input )
    goto gg;
  v8 = 0;                                       // 
                                                // 
                                                // 
                                                // 
  do
  {
    if ( v3 < 'a' || v3 > 'd' )
      goto LABEL_17;
    v9 = input_1[1] - 101;
    if ( v9 > 0x15 )
    {
      input_1 = input;
LABEL_17:
      ++v4;
      goto LABEL_18;
    }
	v10 = v7;
	

    switch ( v3 )
    {
      case 'a':
        v7 = 0;
        X = (X - v9) % 22;
        v8 = *(&byte_410AA8[22 * Y] + X);
		break;
		
      case 'b':
        v7 = 0;
        X = (v9 + X) % 22;
        v8 = *(&byte_410AA8[22 * Y] + X);
        break;
		
      case 'c':
        v7 = 1;
        Y = (Y - v9) % 22;
        v8 = *(&byte_410AA8[22 * Y] + X);
        break;
		
      case 'd':
        v7 = 1;
        Y = (v9 + Y) % 22;
        v8 = *(&byte_410AA8[22 * Y] + X);
        break;
		
      default:
        break;
	}
	

    *(&byte_410AA8[22 * Y] + X) = 0;
    v4 += (v8 ^ 1) + (v10 == v7);
    input_1 = input;

LABEL_18:
    v3 = input_1[2];
    input_1 += 2;
    input = input_1;
  }
  while ( v3 );                                 // 

  if ( Y != 21 || X != 21 )
gg:
    ++v4;
  result = v4 < 0;
  LOBYTE(result) = v4 <= 0;
  return result;
}
```

- 那么byte_13C就是地图了,而且可以顺便判断出switch语句中的abcd,还有地图规模为24 * 24,并且可以看出X,Y值.
- 在patch程序后,成功dump地图.

```
------------------------------------------------------------------------>x
|  .  .  .  .  .  .  .  .  .  #  .  .  #  .  .  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  #  .  .  .  .  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  #  .  .  .  .  .  .  .  .  #  .  .  .  .
|  #  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .  .
|  .  .  .  .  .  .  .  #  .  .  .  .  .  .  .  .  .  .  .  .  #  .
|  .  .  .  #  .  .  #  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  #  .  .  .  .  .  .  #  .  .  .  .  .  .
|  #  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .  #  .  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
|  .  .  .  .  .  #  .  .  .  .  .  .  .  .  .  .  .  .  #  .  .  .
|  #  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
|  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .  .  .  .  .  #
|
|                                      (我事先替换好了0->. , 1->#)
|
V   y
```

- 居然没有显而易见的路径供我们走..... 这是个啥玩意儿啊 \_(:з」∠)\_


# 深入分析 #
- 首先(strlen(input)&1),再一次判断输入是否为0,而且我们可知,strlen为奇数,详情请见位运算hhhhhhh.
- 比较重要的do-while循环,如果v3(input[i])非方向键,那么指针会整体后移.如果奇数位都非方向键,那么GG
- 所以可以确定,方向键和位移数,分别在奇数位和偶数位.
- 那么按正常情况分析,首先猜测为位移数的对应字母,先减去101, 由if(v9>21)的判断区,结合地图为22\*22正方形,下面的\%22和&\(\[22\*y\] \+ x\),可知,这是在限定地图边界.
- 分析主要的switch case可知,a和b是点在X方向的位移,c和d是点在Y方向的位移.
- 左右方向时,会将0赋值给v7,上下时,会将1赋值给v7.
- 移动后会将对应位设置为0 , v4不能为负数,所以条件v8必须为1,即为'#',v10 != v7.所以方向不能重复.

- 综上分析,方向键不能重复为ab或cd.
- 由上图可知,d19 b17 c16 a9 d8 b7 d10 b6  按照对应关系有  dxbvcuandmbldobk

> C:\Users\wangchenyu\Downloads>DC9A4EBEF8F3A11A0D97946F6EBB6640.exe dxbvcuandmbldobk
Congratulations\!  flag\{Y0u\_4re\_4\_G00d\_Ma2e\_Runner\}.

# 总结 #

- 在做题的过程中,我dump下来了6个不同的地图,但是我们可以知道,flag是唯一的,而且在生成地图的时候我也发现了srand和rand函数对地图的操作
- 虽然地图不同,但是可以轻易的得知,走法都是一样的,不同的其实都是一些无用点,那么他是怎么实现的呢,来分析一下生成maze的函数.

- memset一块内存大小为484的地图空间

函数1
```c
void sub_13010B0()
{
  int v0; // ecx@1
  int v1; // esi@1
  int v2; // edx@2
  int v3; // eax@2
  int v4; // esi@4
  int v5; // edx@5
  signed int v6; // eax@6
  char *v7; // ecx@6
  char *v8; // eax@10
  signed int v9; // ecx@10

  v0 = dword_130FF38[0];
  v1 = 0;
  if ( dword_130FF38[0] != -1 )
  {
    v2 = dword_130FF38[0];
    v3 = 0;
    do
    {
      ++v1;
      *(&byte_1310AA8[22 * v2] + dword_130FF3C[v3]) = 1;
      v3 = 2 * v1;
      v2 = dword_130FF38[2 * v1];
    }
    while ( v2 != -1 );
  }
  v4 = 0;
  if ( v0 != -1 )
  {
    v5 = 0;
    do
    {
      v6 = 0;
      v7 = &byte_1310AA8[22 * v0];
      do
      {
        if ( v7[v6] == -1 )
          v7[v6] = 0;
        ++v6;
      }
      while ( v6 < 22 );
      v8 = &byte_1310AA8[dword_130FF3C[v5]];
      v9 = 22;
      do
      {
        if ( *v8 == -1 )
          *v8 = 0;
        v8 += 22;
        --v9;
      }
      while ( v9 );
      v5 = 2 * ++v4;
      v0 = dword_130FF38[2 * v4];
    }
    while ( v0 != -1 );
  }
}
```
函数2
```c
signed int sub_1301000()
{
  int v0; // ecx@1
  int v1; // edx@1
  int v2; // eax@2
  unsigned int v3; // eax@4
  signed int v4; // edi@4
  int Y; // esi@5
  int X; // eax@5
  bool v7; // zf@5
  char *v8; // eax@5
  char *v9; // ecx@8
  signed int result; // eax@9

  v0 = dword_130FFD8[0];
  v1 = 0;
  if ( dword_130FFD8[0] != -1 )
  {
    v2 = 0;
    do
    {
      ++v1;
      *(&byte_1310AA8[22 * v0] + dword_130FFDC[v2]) = 1;
      v2 = 2 * v1;
      v0 = dword_130FFD8[2 * v1];
    }
    while ( v0 != -1 );
  }
  v3 = _time64(0);
  srand(v3);
  v4 = 0;
  do
  {
    Y = rand() % 22;
    X = rand();
    Y *= 22;
    v7 = *(&byte_1310AA8[Y] + X % 22) == -1;
    v8 = &byte_1310AA8[Y] + X % 22;
    if ( v7 )
    {
      *v8 = 1;
      ++v4;
    }
  }
  while ( v4 < 15 );
  v9 = byte_1310AA8;
  do
  {
    result = 0;
    do
    {
      if ( v9[result] == -1 )
        v9[result] = 0;
      ++result;
    }
    while ( result < 22 );
    v9 += 22;
  }
  while ( (signed int)v9 < (signed int)&dword_1310C8C );
  return result;
}
```
分析函数后发现,函数1跑过后,是如下结果(原本的-1被我替换成了2)
```
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  .  .  .  .  .  .  .  #  .  .  .  .  .  .  .  .  #  .  .  .  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  .  .  .  .  .  .  .  #  .  .  .  .  .  .  #  .  .  .  .  .  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
#  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .  .  .  .  
.  2  2  2  2  2  2  2  .  2  2  2  2  2  2  .  2  .  2  2  2  .  
.  .  .  .  .  .  .  .  .  .  .  .  .  .  .  #  .  .  .  .  .  #

```
发现,这就是地图啊,而且只有固定的唯一解,分析函数2后的srand函数和后面赋值函数的作用:
- 随机将2处(也就是memset为-1的数字)随机设置成1(也就是图中的#)然后再遍历地图,将没有涉及到的-1转换成0.

真相大白.

## 国赛re300 !GET !