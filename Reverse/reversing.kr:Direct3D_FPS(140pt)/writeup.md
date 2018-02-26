# Direct3D_FPS
This FPS may defeat any games to top ranking list of the most difficult games.
## notes
- Facing with such a comparatively big computer program, DO be cautious before patching unless you have a clear view of the whole program! 
- When assembly's patching is dismissed, what should be considered about is scripts which can read/patch the memory.
- Do take notice of suspicious strings and windows.
## reverse logic
- Shift+F12 -> suspicious strings
```
.rdata:00405568 00000018 C Game Over! You are dead
.rdata:004055B0 0000000C C Game Clear!
```
- DATA XREF -> suspicious references
```
.rdata:00405568 ; CHAR Text[]
.rdata:00405568 Text            db 'Game Over! You are dead',0
.rdata:00405568                                         ; DATA XREF: WinMain(x,x,x,x)+49Ao
... ...
.rdata:004055B0 ; CHAR aGameClear[]
.rdata:004055B0 aGameClear      db 'Game Clear!',0      ; DATA XREF: sub_4039C0+1Do
.rdata:004055BC                 align 10h
```
- FUNC -> sub_4039C0
```
(Assembly)
.text:004039C0 sub_4039C0      proc near               ; CODE XREF: WinMain(x,x,x,x):loc_402F4Cp
.text:004039C0                 mov     eax, offset dword_409194
.text:004039C5
.text:004039C5 loc_4039C5:                             ; CODE XREF: sub_4039C0+14j
.text:004039C5                 cmp     dword ptr [eax], 1
.text:004039C8                 jz      short locret_403A01
.text:004039CA                 add     eax, 210h
.text:004039CF                 cmp     eax, offset unk_40F8B4
.text:004039D4                 jl      short loc_4039C5
.text:004039D6                 mov     eax, hWnd
.text:004039DB                 push    40h             ; uType
.text:004039DD                 push    offset aGameClear ; "Game Clear!"
.text:004039E2                 push    offset byte_407028 ; lpText
.text:004039E7                 push    eax             ; hWnd
.text:004039E8                 call    ds:MessageBoxA
.text:004039EE                 mov     ecx, hWnd
.text:004039F4                 push    0               ; lParam
.text:004039F6                 push    0               ; wParam
.text:004039F8                 push    2               ; Msg
.text:004039FA                 push    ecx             ; hWnd
.text:004039FB                 call    ds:SendMessageA
.text:00403A01
.text:00403A01 locret_403A01:                          ; CODE XREF: sub_4039C0+8j
.text:00403A01                 retn
.text:00403A01 sub_4039C0      endp
```
```
(F5 -> C)
int *sub_4039C0()
{
  int *result; // eax@1

  result = &dword_409194;
  while ( *result != 1 )
  {
    result += 132;
    if ( (signed int)result >= (signed int)&unk_40F8B4 )
    {
      MessageBoxA(hWnd, &byte_407028, "Game Clear!", 0x40u);
      return (int *)SendMessageA(hWnd, 2u, 0, 0);
    }
  }
  return result;
}
```
- Retrospect &byte_407028 to look for the title of this MessageBox (assuming that the title is the flag)
```
.data:00407028 ; const CHAR byte_407028
.data:00407028 byte_407028     db 43h                  ; DATA XREF: sub_403400+2Dw
.data:00407028                                         ; sub_4039C0+22o
.data:00407029                 db  6Bh ; k
.data:0040702A                 db  66h ; f
.data:0040702B                 db  6Bh ; k
.data:0040702C                 db  62h ; b
.data:0040702D                 db  75h ; u
.data:0040702E                 db  6Ch ; l
.data:0040702F                 db  69h ; i
.data:00407030                 db  4Ch ; L
.data:00407031                 db  45h ; E
.data:00407032                 db  5Ch ; \
.data:00407033                 db  45h ; E
.data:00407034                 db  5Fh ; _
.data:00407035                 db  5Ah ; Z
.data:00407036                 db  46h ; F
.data:00407037                 db  1Ch
.data:00407038                 db    7
.data:00407039                 db  25h ; %
.data:0040703A                 db  25h ; %
.data:0040703B                 db  29h ; )
.data:0040703C                 db  70h ; p
.data:0040703D                 db  17h
.data:0040703E                 db  34h ; 4
.data:0040703F                 db  39h ; 9
.data:00407040                 db    1
.data:00407041                 db  16h
.data:00407042                 db  49h ; I
.data:00407043                 db  4Ch ; L
.data:00407044                 db  20h
.data:00407045                 db  15h
.data:00407046                 db  0Bh
.data:00407047                 db  0Fh
.data:00407048                 db 0F7h ; 
.data:00407049                 db 0EBh ; 
.data:0040704A                 db 0FAh ; 
.data:0040704B                 db 0E8h ; 
.data:0040704C                 db 0B0h ; 
.data:0040704D                 db 0FDh ; 
.data:0040704E                 db 0EBh ; 
.data:0040704F                 db 0BCh ; 
.data:00407050                 db 0F4h ; 
.data:00407051                 db 0CCh ; 
.data:00407052                 db 0DAh ; 
.data:00407053                 db  9Fh ; 
.data:00407054                 db 0F5h ; 
.data:00407055                 db 0F0h ; 
.data:00407056                 db 0E8h ; 
.data:00407057                 db 0CEh ; 
.data:00407058                 db 0F0h ; 
.data:00407059                 db 0A9h ; 
.data:0040705A                 db    0
.data:0040705B                 db    0
.data:0040705C                 db    0
.data:0040705D                 db    0
.data:0040705E                 db    0
.data:0040705F                 db    0
``` 
*invisible characters have occured*
- DATA XREF -> suspicious function -> sub_403400
```
(Assembly)
.text:00403400 sub_403400      proc near               ; CODE XREF: WinMain(x,x,x,x)+750p
.text:00403400                 push    ecx
.text:00403401                 call    sub_403440
.text:00403406                 cmp     eax, 0FFFFFFFFh
.text:00403409                 jz      short loc_40343E
.text:0040340B                 mov     ecx, eax
.text:0040340D                 imul    ecx, 210h
.text:00403413                 mov     edx, dword_409190[ecx]
.text:00403419                 test    edx, edx
.text:0040341B                 jg      short loc_403435
.text:0040341D                 mov     dword_409194[ecx], 0
.text:00403427                 mov     cl, byte_409184[ecx]
.text:0040342D                 xor     byte_407028[eax], cl
.text:00403433                 pop     ecx
.text:00403434                 retn
.text:00403435 ; ---------------------------------------------------------------------------
.text:00403435
.text:00403435 loc_403435:                             ; CODE XREF: sub_403400+1Bj
.text:00403435                 add     edx, 0FFFFFFFEh
.text:00403438                 mov     dword_409190[ecx], edx
.text:0040343E
.text:0040343E loc_40343E:                             ; CODE XREF: sub_403400+9j
.text:0040343E                 pop     ecx
.text:0040343F                 retn
.text:0040343F sub_403400      endp
```
```
(F5 -> C)
int __thiscall sub_403400(void *this)
{
  int result; // eax@1
  int v2; // ecx@2
  int v3; // edx@2

  result = sub_403440(this);
  if ( result != -1 )
  {
    v2 = 132 * result;
    v3 = dword_409190[132 * result];
    if ( v3 > 0 )
    {
      dword_409190[v2] = v3 - 2;
    }
    else
    {
      dword_409194[v2] = 0;
      *((_BYTE *)&byte_407028 + result) ^= byte_409184[v2 * 4];
    }
  }
  return result;
}
```
- Retrospect byte_409184 to get the real flag
```
.data:00409184 ; char byte_409184[]
.data:00409184 byte_409184     db ?                    ; DATA XREF: sub_403400+27r
.data:00409185                 align 10h
```
- However, nothing found...
- Run this game with the monitoring of IDApro and use IDC to dump byte_409184
```
IDC>auto i;for(i=0;i<50;i++)Message("%d ", Byte(0x189184 + i*132*4));
0 4 8 12 16 20 24 28 32 36 40 44 48 52 56 60 64 68 72 76 80 84 88 92 96 100 104 108 112 116 120 124 128 132 136 140 144 148 152 156 160 164 168 172 176 180 184 188 192 196 
```
- Then reverse script can help you get the flag
## END