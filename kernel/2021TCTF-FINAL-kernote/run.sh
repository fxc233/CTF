#!/bin/sh
qemu-system-x86_64 \
-m 128M \
-kernel ./bzImage \
-hda ./rootfs.img \
-append "console=ttyS0 quiet root=/dev/sda rw init=/init oops=panic panic=1 panic_on_warn=1 kaslr pti=on" \
-monitor /dev/null \
-smp cores=2,threads=2 \
-nographic \
-cpu kvm64,+smep,+smap \
-no-reboot \
-snapshot