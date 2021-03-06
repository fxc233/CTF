#!/bin/sh
cd /home/ctf
qemu-system-x86_64 \
-m 64M \
-kernel ./bzImage \
-initrd  ./rootfs.img \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 kaslr" \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic \
-monitor /dev/null \
-smp cores=2,threads=1 \
-cpu qemu64,+smep,+smap