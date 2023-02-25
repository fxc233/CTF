//gcc main.c -o main -lseccomp
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/prctl.h>
#include<linux/filter.h>
#include<linux/seccomp.h>
#include<seccomp.h>

int show_num = 2;
int edit_num = 4;

typedef struct SEcret
{
	char* secret;
	char* tmp_secret;
	struct SEcret* next;
}Secret;

Secret* head;

void sandbox()
{
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
	seccomp_load(ctx);
	return;
}

void init()
{
        setbuf(stdin, 0);
        setbuf(stdout, 0);
        setbuf(stderr, 0);
        sandbox();
        //size_t* ptr = malloc(0x10);
        //ptr[0] = (size_t)(&puts);
        puts("Please quickly crack X1c's secret");
        return;
}

void menu()
{
	puts("1.add a secret");
	puts("2.delete a secret");
	puts("3.peep a secret");
	puts("4.distort a secret");
	printf(">> ");
}

int my_read()
{
	char choice[8];
	read(0 , choice , 8);
	return atoi(choice);
}

void add()
{
	head = (Secret*)malloc(0x20);
	head->tmp_secret = (char*)malloc(0xd0);
	head->secret = (char*)malloc(0xd0);
	puts("Please input your secret");
	read(0,(void*)head->secret,0xd0);
	memcpy(head->tmp_secret,head->secret,strlen(head->secret));
	return;
}

void delete()
{
	free((void*)head->secret);
	free((void*)head->tmp_secret);
	head->secret = NULL;
	return;
}

void show()
{
	puts("you only have two chances to peep a secret");
	if(show_num)
	{
		write(1,(void*)head->tmp_secret,8);
		show_num--;
	}
	else
		puts("no chance to peep");
	return;
}

void edit()
{
	puts("you only have four chances to distort a secret");
	if(edit_num)
	{
		puts("Please input content");
		read(0,(void*)head->tmp_secret,0xd0);
		edit_num--;
	}
	else
		puts("no chance to distort");
	return;
}

int main()
{
	int choice = 0;
	init();
	while(1)
		{
			while(1)
			{
				menu();
				choice = my_read();
				if(choice > 0)
					break;
				else
					exit(0);
			}
			switch(choice)
			{
				case 1:
					add();
					continue;
				case 2:
					delete();
					continue;
				case 3:
					show();
					continue;
				case 4:
					edit();
					continue;
				default:
					puts("Invaild choice");
					return 0;
			}
			
		}
	return 0;
}