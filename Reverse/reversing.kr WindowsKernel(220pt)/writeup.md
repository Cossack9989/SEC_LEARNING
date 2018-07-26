# Windows Kernel
### Analysis of WindowsKernel.exe
###### Winmain(0x00401000):
```
push	0					;dwInitParam
push 	offset DialogFunc	;lpDialogFunc
push	0					;hWndParent
push	65h					;lpTemplateName
push	eax					;hInstance
call	ds:DialogBoxParamW
```
###### DialogFunc(0x00401020):
```
BOOL __stdcall DialogFunc(HWND hWnd, UINT a2, WPARAM a3, LPARAM a4)
{
	if ( a2 == 272 )							//Timer set
	{
		SetDlgItemTextW(hWnd, 1001, L"Wait.. ");
		SetTimer(hWnd, 0x464u, 0x3E8u, 0);
		return 1;
	}
	if ( a2 != 273 )
	{
		if ( a2 == 275 )						//Error ocurr
		{
			KillTimer(hWnd, 0x464u);
			HandleError(hWnd);
			return 1;
		}
		return 0;
	}
	if ( (unsigned __int16)a3 == 2 )			//Dialog end
	{
		SetDlgItemTextW(hWnd, 1001, L"Wait.. ");
		CloseProc();
		EndDialog(hWnd, 2);
		return 1;
	}
	if ( (unsigned __int16)a3 == 1002 )			//Unknown
	{
		if ( a3 >> 16 == 1024 )
		{
			Sleep(0x1F4u);
			return 1;
		}
		return 1;
	}
	if ( (unsigned __int16)a3 != 1003 )
		return 0;
	check(hWnd);								//Judge the input
	return 1;
}
```
###### check(0x00401110):
```
HWND __thiscall check(HWND hDlg)
{
	HWND v1; // edi
	HWND result; // eax
	HWND v3; // eax
	HWND v4; // eax
	HWND v5; // eax
	WCHAR String; // [esp+8h] [ebp-204h]

	v1 = hDlg;
	GetDlgItemTextW(hDlg, 1003, &String, 512);
	if ( lstrcmpW(&String, L"Enable") )
	{
		result = (HWND)lstrcmpW(&String, L"Check");
		if ( !result )
		{
			if ( click(v1, 0x2000u) == 1 )
				MessageBoxW(v1, L"Correct!", L"Reversing.Kr", 0x40u);
			else
				MessageBoxW(v1, L"Wrong", L"Reversing.Kr", 0x10u);
			SetDlgItemTextW(v1, 1002, &word_4021F0);
			v5 = GetDlgItem(v1, 1002);
			EnableWindow(v5, 0);
			result = (HWND)SetDlgItemTextW(v1, 1003, L"Enable");
		}
	}
	else if ( click(v1, 0x1000u) )
	{
		v3 = GetDlgItem(v1, 1002);
		EnableWindow(v3, 1);
		SetDlgItemTextW(v1, 1003, L"Check");
		SetDlgItemTextW(v1, 1002, &word_4021F0);
		v4 = GetDlgItem(v1, 1002);
		result = SetFocus(v4);
	}
	else
	{
		result = (HWND)MessageBoxW(v1, L"Device Error", L"Reversing.Kr", 0x10u);
	}
	return result;
}
```

两次click，arg1==0x1000是点击Enable，按钮变成Check；arg1==0x2000是点击Check，回显Correct或者Wrong。

后来翻了夜影老哥的WP，发现这个0x1000和0x2000是dwIoControlCode，即DeviceIoControl的arg1，而dwIoControlCode值就是Windows内核中宏定义CTL_CODE所定义的。

详情请看[MSDN对CTL_CODE的解释](https://docs.microsoft.com/en-us/previous-versions/windows/embedded/ms902086(v=msdn.10))
###### click(0x00401280):
```
int __usercall sub_401280@<eax>(HWND a1@<edi>, DWORD dwIoControlCode)
{
	HANDLE v2; // esi
	int result; // eax
	DWORD BytesReturned; // [esp+4h] [ebp-8h]
	int OutBuffer; // [esp+8h] [ebp-4h]

	v2 = CreateFileW(L"\\\\.\\RevKr", 0xC0000000, 0, 0, 3u, 0, 0);
	if ( v2 == (HANDLE) - 1 )
	{
		MessageBoxW(a1, L"[Error] CreateFile", L"Reversing.Kr", 0x10u);
		result = 0;
	}
	else if ( DeviceIoControl(v2, dwIoControlCode, 0, 0, &OutBuffer, 4u, &BytesReturned, 0) )
	{
		CloseHandle(v2);
		result = OutBuffer;
	}
	else
	{
		MessageBoxW(a1, L"[Error] DeviceIoControl", L"Reversing.Kr", 0x10u);
		result = 0;
	}
	return result;
}
```
click函数内很明显通过DeviceIoControl与键盘设备进行了交互(快看这里有dwIoControlCode)，并调用了WinKer.sys中的函数

接下来分析WinKer.sys

### Analysis of WinKer.sys
###### KeyBoardInput(0x00011266):
这里通过静态分析找到了接收键盘设备输入的函数
```
void __stdcall getInput(struct _KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
  char input; // al

  input = READ_PORT_UCHAR((PUCHAR)0x60);
  sub_111DC(input);
}
```
READ_PORT_UCHAR是Windows内核I/O中从指定的PORT读入一字节数据的函数，其参数(PUCHAR)PORT在此为0x60，而大多数PC键盘控制器在PORT0x60与0x64是可寻址的，故此处为从键盘控制器逐次读入1byte。
###### Judge(0x000111DC,0x00011156,0x000110D0):
这些理解起来都简单。
在第一个Judge中通过switch(judgenum)先检查前3个byte的值，再检查最后1byte值，若正确则judgenum=100，并进入下一个Judge；
在第二个Judge中先对第5到最后的byte进行异或0x12的处理，再通过switch(judgenum)检查第5到7个byte，最后检查第8个byte，若正确则judgenum=200，并进入下一个Judge；
第三个Judge也是类似，只不过又对最后四字节进行了异或5的处理。

### Solve
解密脚本如下
```
s=[0xa5,0x92,0x95,0xb0,0xb2,0x85,0xa3,0x86,0xb4,0x8f,0x8f,0xb2]
for i in range(4):
	s[i+4]^=0x12
	s[i+8]^=0x12
	s[i+8]^=0x5
mid=''
for i in s:
	mid+=str(hex(i))[2:]
print mid
```
得到a59295b0a097b194a39898a5
对应[ScanCode码表](https://blog.csdn.net/cmdasm/article/details/10168907)解码得keybdinthook