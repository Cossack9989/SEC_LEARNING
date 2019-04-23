### Virtual

(作为部分WP已投稿先知)

考察PWN选手逆向与编写shellcode(大雾)的能力？？？漏洞利用点在于load和save对position范围没有校验导致的越界读写

##### 利用流程

- 通过load获取堆上的模拟数据栈所存储的模拟数据栈基址 (push push load)
- 又因无PIE，所得基址与GOT段地址sub得到越界读的position (push sub div load)
- 越界读得到proc.GOT段所存储的libc内函数绝对地址pop泄露一下确定libc版本（该功能不在最终exp中）
- 如法炮制再获取一次越界写的position，用计算出的system(push add)覆写proc.GOT段的puts函数指针 (push push load push sub div save)
- 输出进程名的时候执行system(procname),getshell!

##### 坑

nil

##### payload

//是真的不需要exp.py

###### 未确定libc版本时

- 输入进程名时 输入 `$0`
- 输入Instruction时 输入 `push push load push sub div load pop`
- 输入stackdata时 输入 `8 -4 4210720`
- 所得到的时`free`的地址，查询libcdatabase得到libc版本

###### 确定libc版本后

- 输入进程名时 输入 `$0`
- 输入Instruction时 输入 `push push load push sub div load push add push push load push sub div save`
- 输入stackdata时 输入 `8 -4 4210720 -296208 8 -5 4210728`(-296208是我使用的libc下&system-&free)
- getshell
