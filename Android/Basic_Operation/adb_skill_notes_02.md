# Note02
- How to use fruitful commands while debugging Android?
- just install busybox.
## Installing process
- push busybox to an Android platform
```
root@MiWiFi-R3-srv:~/Downloads# adb push ~/Downloads/busybox /mnt/sdcard/busybox
[100%] /mnt/sdcard/busybox
```
- give Higher authority to debugger in /system
```
mount -o remount,rw -t yaffs2 /dev/block/mtdblock3 /system
```
- then copy busybox into /system/xbin 
```
cat /mnt/sdcard/busybox > /system/xbin/busybox
```
- install it
```
chmod 777 busybox
busybox --install /system/xbin
```
- Finally succeed!