### How to exploit 2ez4u

- leak libcbase by { unsorted-bin's bk + misplaced heap }
- leak heapbase by { large-bin's `bk_nextsize`}
- fastbin attack by { misplaced heap + UAF }

### details

```c
struct apple{
    int inuse;
    int desLen;
    struct apple_des*{
        int color;
        int num;
        __int64 value;
        __int64 index;
        char description[desLen];
    }
}
```

###### misplaced heap

```
|=======| |=======|->bin1
+-------+ +-------+
|0x18jnk| |0x18jnk|
|-------| |-------|
|   d0  | |   d1  |
|       | |       |
|       | |=======|->bin2
|       | +-------+
|       | |0x18jnk|
|       | |-------|
|       | |   d2  |
|       | |       |
+-------+ +-------+
//STAGE1:
//place cutted-unsortedbin's bk at &bin2+0x18 and leak
//STAGE2:
//change bin2 from cutted-unsortedbin to fastbin
//change bin2's fd by d0(UAF)
```
