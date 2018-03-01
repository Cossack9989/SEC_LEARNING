# RingZer0 Authenticator


- OD跟了一波,只发现username必为RingZer0,随后IDA分析主函数,发现关键函数sub_4014A0,此时程序将username和password传入.
- 函数得到返回值为1即可,函数里先判定username,随后判定password是否为纯数字.
- 在函数尾,username和password分别传入两个函数,返回两个数组,然后对比其值
``` C
int __cdecl sub_4014A0(_BYTE *name, _BYTE *pass)
{
  bool v2; // zf@1
  const char *v3; // edi@1
  signed int v4; // ecx@1
  _BYTE *v5; // esi@1
  signed int v6; // ecx@5
  _BYTE *v7; // edi@5
  int i; // eax@8
  char *v9; // esi@12
  char *v10; // eax@12

  v2 = 0;
  v3 = "RingZer0";
  v4 = 9;
  v5 = name;
  do
  {
    if ( !v4 )
      break;
    v2 = *v5++ == *v3++;
    --v4;
  }
  while ( v2 );
  if ( !v2 )
    return 0;
  v6 = -1;
  v7 = pass;
  do
  {
    if ( !v6 )
      break;
    v2 = *v7++ == 0;
    --v6;
  }
  while ( !v2 );
  i = 0;
  if ( v6 == -17 )
  {
    while ( (pass[i] - 48) <= 9u )
    {
      if ( ++i == 15 )
      {
        v9 = sub_401334(name);
        v10 = sub_401450(pass);
        if ( *v10 == v9[1] && v10[1] == v9[5] && v10[2] == v9[8] && v10[3] == v9[14] )
          return v10[4] == v9[17];
        return 0;
      }
    }
    return 0;
  }
  return i;
}
```
- 对于name的操作过于繁琐,这里采用dump内存来获得数组,对于pass加密部分,因为是15长度的密码3字节为一组生成一个密匙位,这里选择爆破.
```python
a = [152,151,120,15,21]
flag=''
for i in range(5):
    for i1 in range(0x30,0x3A):
        for i2 in range(0x30, 0x3A):
            for i3 in range(0x30, 0x3A):
                if a[i] == 96 - i2 + -70 * (i1-48) + 13*(i3-48):
                    flag += chr(i1)+chr(i2)+chr(i3)

print(flag)
```
username:RingZer0</br>
password:008018066123249</br>

![](./image/123.jpg)