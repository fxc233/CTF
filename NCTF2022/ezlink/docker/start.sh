#!/bin/sh
# Add your startup script

# DO NOT DELETE
/etc/init.d/xinetd start;

while :
do
	rm /home/ctf/flag*
	cp /flag "/home/ctf/flag`head /dev/urandom |cksum |md5sum |cut -c 1-20`"
	sleep 5
done