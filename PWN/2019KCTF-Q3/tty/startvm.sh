#!/bin/sh
cd `dirname $0`
#stty intr ^]
./qemu_cmd ./bzImage ./initramfs.cpio

