title: 上海市ctf-re200-juckcode
categories:
- 二进制
---
# 正向解析juckcode #
 一个二进制文件和一份加密后的flag,显然逆算法,扔进IDA,各种分析不出函数...怎么回事呢用OD打开查看下,有好多段可疑的汇编指令大概是pushad jmp 大量无用代码 popad
 花指令get,写脚本全部nop掉,用IDA打开处理好的文件,发现,居然还是不能F5,又发现了一段异常代码,两个jmp一个E8,nop掉E8居然就可以了,OD启动,提取目标的一段字节码.
 ```python
 b =    '\x60\xE9\x31\x00\x00\x00\x8B\xEC\x6A\xFF\x68\x33\x22\x11\x00\x68\x11\x22\x33\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x58\x64\xA3\x00\x00\x00\x00\x58\x58\x58\x58\x8B\xE8\xB8\x50\x10\x40\x00\x50\xE8\xC3\x61'
a = '\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
c = '\x0F\x8E\x07\x00\x00\x00\x0F\x85\x01\x00\x00\x00\xE8'
d = '\x0F\x8E\x07\x00\x00\x00\x0F\x85\x01\x00\x00\x00\x90'
f = open('juckcode.exe', 'rb')
da = f.read()
print da.count(b)
print da.count(c)
da = da.replace(b,a).replace(c,d)
print da.count(b)
print da.count(c)
w = open('bacjuck.exe', 'wb')
w.write(da)
w.close()
f.close()
 ```
 处理后成功看到伪代码.程序是C++写的,而且封装贼鸡儿恶心,不过大概看到了一些可以看的懂的函数.
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ST10_4
  char *v4; // eax
  int v5; // ST10_4
  char *v6; // eax
  int v7; // ST10_4
  char *v8; // eax
  int v9; // ebx
  int v10; // ST10_4
  char *v11; // eax
  int v12; // eax
  unsigned int v13; // eax
  int v14; // ST10_4
  int v15; // eax
  char v17; // [esp+10h] [ebp-9DCh]
  char v18; // [esp+28h] [ebp-9C4h]
  char v19; // [esp+40h] [ebp-9ACh]
  int v20; // [esp+58h] [ebp-994h]
  int v21; // [esp+5Ch] [ebp-990h]
  char *v22; // [esp+60h] [ebp-98Ch]
  int v23; // [esp+64h] [ebp-988h]
  BOOL v24; // [esp+68h] [ebp-984h]
  char *v25; // [esp+6Ch] [ebp-980h]
  char *v26; // [esp+70h] [ebp-97Ch]
  unsigned int m; // [esp+74h] [ebp-978h]
  unsigned int j; // [esp+78h] [ebp-974h]
  unsigned int i; // [esp+7Ch] [ebp-970h]
  unsigned int n; // [esp+80h] [ebp-96Ch]
  const char *v31; // [esp+84h] [ebp-968h]
  unsigned int k; // [esp+88h] [ebp-964h]
  bool v33; // [esp+8Fh] [ebp-95Dh]
  unsigned int l; // [esp+90h] [ebp-95Ch]
  char v35; // [esp+94h] [ebp-958h]
  char v36; // [esp+14Ch] [ebp-8A0h]
  char v37; // [esp+164h] [ebp-888h]
  char v38; // [esp+17Ch] [ebp-870h]
  char v39; // [esp+194h] [ebp-858h]
  char v40; // [esp+1ACh] [ebp-840h]
  char input; // [esp+1C4h] [ebp-828h]
  char v42; // [esp+1DCh] [ebp-810h]
  char v43; // [esp+1DDh] [ebp-80Fh]
  char Src; // [esp+5DCh] [ebp-410h]
  char Dst; // [esp+5DDh] [ebp-40Fh]
  char v46; // [esp+5DEh] [ebp-40Eh]
  char v47[1021]; // [esp+5DFh] [ebp-40Dh]
  int v48; // [esp+9E8h] [ebp-4h]

  sub_4038A0(0xB8u);
  sub_4039F0("./flag", 1, 64, 1);
  v48 = 0;
  sub_401E00(&input);
  LOBYTE(v48) = 1;
  if ( !(unsigned __int8)sub_403970(&v35) )
  {
    sub_4050D0(std::cout, "error in open flag.");
    exit(0);
  }
  sub_405410(&v35, &input);
  v3 = len(&input);
  v4 = (char *)sub_4038C0(&input);
  base64encode((int)&v40, v4, v3);
  LOBYTE(v48) = 2;
  for ( i = 0; i < len(&input); ++i )
  {
    v26 = sub_401C80(&input, i);
    *v26 += 64;
  }
  v5 = len(&input);
  v6 = (char *)sub_4038C0(&input);
  base64encode((int)&v36, v6, v5);
  LOBYTE(v48) = 3;
  for ( j = 0; j < len(&input); ++j )
  {
    v25 = sub_401C80(&input, j);
    *v25 <<= 7;
  }
  v7 = len(&input);
  v8 = (char *)sub_4038C0(&input);
  base64encode((int)&v37, v8, v7);
  LOBYTE(v48) = 4;
  for ( k = 0; k < len(&input); ++k )
  {
    v9 = *sub_401C80(&input, k) - 158;
    *sub_401C80(&input, k) = v9;
  }
  v10 = len(&input);
  v11 = (char *)sub_4038C0(&input);
  base64encode((int)&v38, v11, v10);
  LOBYTE(v48) = 5;
  Src = 0;
  memset(&Dst, 0, 0x3FFu);
  for ( l = 0; l < len(&v40); ++l )
  {
    if ( *sub_401C80(&v40, l) != 61 )
      *(&Src + 4 * l) = *sub_401C80(&v40, l);
    *(&Dst + 4 * l) = *sub_401C80(&v36, l);
    v47[4 * l] = *sub_401C80(&v37, l);
    *(&v46 + 4 * l) = *sub_401C80(&v38, l);
  }
  sub_401D90(&Src);
  LOBYTE(v48) = 6;
  sub_4017D0(&v39, &v19);
  LOBYTE(v48) = 8;
  std::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string<char,std::char_traits<char>,std::allocator<char>>(&v19);
  v42 = 0;
  memset(&v43, 0, 0x3FFu);
  for ( m = 0; ; ++m )
  {
    sub_401D90(&Src);
    LOBYTE(v48) = 9;
    v12 = sub_4017D0(&v17, &v18);
    v23 = v12;
    v13 = len(v12);
    v24 = m < v13;
    v33 = m < v13;
    std::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string<char,std::char_traits<char>,std::allocator<char>>(&v17);
    LOBYTE(v48) = 8;
    std::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string<char,std::char_traits<char>,std::allocator<char>>(&v18);
    if ( !v33 )
      break;
    v14 = (unsigned __int8)*sub_401C80(&v39, m);
    sub_405BA0(&v42, 1024, "%s%.2hhx", (unsigned int)&v42);
  }
  for ( n = 0; ; ++n )
  {
    v31 = &v42;
    v22 = &v43;
    v31 += strlen(v31);
    v21 = ++v31 - &v43;
    if ( n >= v31 - &v43 )
      break;
    *(&v42 + n) += 16;
  }
  v15 = sub_4050D0(std::cout, &v42);
  std::basic_ostream<char,std::char_traits<char>>::operator<<(v15, sub_405430);
  v20 = 0;
  LOBYTE(v48) = 5;
  std::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string<char,std::char_traits<char>,std::allocator<char>>(&v39);
  LOBYTE(v48) = 4;
  std::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string<char,std::char_traits<char>,std::allocator<char>>(&v38);
  LOBYTE(v48) = 3;
  std::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string<char,std::char_traits<char>,std::allocator<char>>(&v37);
  LOBYTE(v48) = 2;
  std::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string<char,std::char_traits<char>,std::allocator<char>>(&v36);
  LOBYTE(v48) = 1;
  std::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string<char,std::char_traits<char>,std::allocator<char>>(&v40);
  LOBYTE(v48) = 0;
  std::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string<char,std::char_traits<char>,std::allocator<char>>(&input);
  v48 = -1;
  sub_403870();
  return v20;
}
```

首先判断了下文件是否读取成功,随后base64.base64encode大概的传参顺序是加密后的字符串,待加密的flag的首地址,flag的长度.大概的顺序就是:

- input加密一次
- input每一位加64
- input加密一次
- input每一位再次右移7位
- input加密一次
- input每一位减去158
- input加密一次

这样会得到四个字符base64后的字符长度相同的字符串.随后到达

```c
  memset(&Dst, 0, 0x3FFu);
  for ( l = 0; l < len(&v40); ++l )
  {
    if ( *sub_401C80(&v40, l) != 61 )
      *(&Src + 4 * l) = *sub_401C80(&v40, l);
    
    *(&Dst + 4 * l) = *sub_401C80(&v36, l);
    v47[4 * l] = *sub_401C80(&v37, l);
    *(&v46 + 4 * l) = *sub_401C80(&v38, l);
  }
```

- v36 v37 v38 v40是刚才base64的字符串
- sub\_401C80函数,是取下标操作,\*sub\_401C80(&v37, l)的意思就是v37[l]
- 查看v47,v46,Dst,Src,发现其在栈内的分布是连续的四位
- 所以可以看出来,依次从四个base后的字符串中提取出一个,组成一个新的base后的字符串

随后程序进行一次base64decode,将解码后的16进制转换成字符串,然后每一位减去16,打印出来.

# 开始逆向 #

首先还原16进制,然后将其base64encode,提取出i%4==0的对应位,然后base64encode即可.
下面是解密代码:

```python
import base64

s = "FFIF@@IqqIH@sGBBsBHFAHH@FFIuB@tvrrHHrFuBD@qqqHH@GFtuB@EIqrHHCDuBsBqurHH@EuGuB@trqrHHCDuBsBruvHH@FFIF@@AHqrHHEEFBsBGtvHH@FBHuB@trqrHHADFBD@rquHH@FurF@@IqqrHHvGuBD@tCDHH@EuGuB@tvrrHHCDuBD@tCDHH@FuruB@tvrIH@@DBBsBGtvHH@GquuB@EIqrHHvGuBsBtGEHH@EuGuB@tvrIH@BDqBsBIFEHH@GFtF@@IqqrHHEEFBD@srBHH@GBsuB@trqrHHIFFBD@rquHH@FFIuB@tvrrHHtCDB@@"
s1 = ""
base = 'ABCDEFGHIJKLMN0PQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for i in s:
    s1 += (chr(ord(i) - 0x10))

flag = ''
for i in range(len(s1) / 2):
    if i % 3 == 0:
        flag += base[int(s1[i * 2:i * 2 + 2], base=16) >> 2]
flag += '=' * (4 - len(flag) % 4)
print base64.b64decode(flag)
```

## flag: flag{juck_code_cannot_stop_you_reversing} ##
