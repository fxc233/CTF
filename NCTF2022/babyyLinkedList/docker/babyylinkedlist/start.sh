#!/bin/sh
# Add your startup script
# start ctf-xinetd
/etc/init.d/xinetd start; 
trap : TERM INT; 
sleep infinity & wait\
