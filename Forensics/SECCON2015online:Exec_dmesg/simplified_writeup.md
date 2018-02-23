#Exec dmesg
## GEMU needed first
Assuming that we install a GEMU for Windows X64, commands should be used as the following shows.
>     .\qemu-img create -f qcow2 test-vm-1.qcow2 8G
>     .\qemu-system-x86_64 -m 1024 test-vm-1.qcow2 -cdrom C:/Users/76923/Desktop/image/tiny_linux/core-current.iso
Then this tiny Linux system starts to run.
Or, if you have already installed this virtual machine, you have to command like this:
>     .\qemu-system-x86_64 -m 1024 test-vm-1.qcow2
## What is dmesg?
**Google first**
- Command dmesg is used to check and control the kernel ring buffer.
- Boot information is stored in directory /var/log/dmesg [Click here to know more](http://man.linuxde.net/dmesg)
However, when I used command 'dmesg' on this VM, its feedback was 'Applet not found'.Then I enter thr directory /var/log but nothing found apart from file autologin and wtmp.
Consequently, I searched and searched but got no achievement.
**Baidu also matters**
[dmesg&kmsg](http://blog.csdn.net/zlcchina/article/details/24195331)
[](https://baike.baidu.com/item/dmesg/271976?fr=aladdin)
That's crucial to this challenge.
>     cat /proc/kmsg | grep SECCON
Flag emerged.