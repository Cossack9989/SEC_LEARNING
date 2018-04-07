# Notes_01
- First and foremost, you should have a rooted Android phone and adb tools on your computer.
- Then let's start!
## adb pull but reply 'Permission denied'
- Such as this: 
```
root@localhost:~# adb pull /data/system/locksettings.db /root/Desktop/lockingsettings.db
adb: error: failed to copy '/data/system/locksettings.db' to '/root/Desktop/lockingsettings.db': Permission denied
```
- Reason: Low Authority of debugger compared with Authority`system`
### Method_01(Recommanded):
- Authority of /mnt/sdcard is low enough which allows the debugger to pull
- First Try:
```
root@android:/ # cp /data/system/locksettings.db /mnt/sdcard                   
sh: cp: not found
```
- Then we use `cat` && `>` to replace `cp`
```
root@android:/mnt/sdcard # cat /data/system/locksettings.db > locksettingstest.db
```
- Finally succeed!
```
root@localhost:~# adb pull /mnt/sdcard/locksettingstest.db /root/Desktop/lockingsettings.db
[100%] /mnt/sdcard/locksettingstest.db
```
### Method_02:
>    adb shell \n
>    su root \n
>    cd /data/system \n
>    chmod 664 lockingsettings.db \n
- Then as above.