#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <sys/prctl.h>

typedef struct node
{
	char* date_ptr;
	struct node* next;
	size_t size;
}Node;

Node *head;
int show_count = 1, edit_count = 2;

/*
void sandbox()
{
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    struct sock_filter sfi[] ={
        {0x20,0x00,0x00,0x00000004},
        {0x15,0x00,0x05,0xC000003E},
        {0x20,0x00,0x00,0x00000000},
        {0x35,0x00,0x01,0x40000000},
        {0x15,0x00,0x02,0xFFFFFFFF},
        {0x15,0x01,0x00,0x0000003B},
        {0x06,0x00,0x00,0x7FFF0000},
        {0x06,0x00,0x00,0x00000000}
    };
    struct sock_fprog sfp = {8, sfi};
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sfp);
}
*/
void init()
{
        setbuf(stdin, 0);
        setbuf(stdout, 0);
        setbuf(stderr, 0);
        puts("Welcome to NCTF2022 hacker");
        //sandbox();
}

void menu()
{
	puts("1.add a node");
	puts("2.delete a node");
	puts("3.show a node");
	puts("4.edit a node");
	printf(">> ");
}

int my_read()
{
	char v1[8];
	read(0 , v1 , 8);
	return atoi(v1);
}

void add()
{
	unsigned int size;
	Node* ptr;
	char* tmp;

	puts("Please input size");
	size = my_read();
	tmp = (char*)malloc(size);
	while(1)
	{
		if(head == NULL)
		{
			head = malloc(sizeof(Node));
			head->size = size;
			head->date_ptr = tmp;
			break;
		}
		else
		{
			ptr = head;
			head = malloc(sizeof(Node));
			head->next = ptr;
			head->size = size;
			head->date_ptr = tmp;
			break;
		}
	}
	puts("Please input content");
	read(0,head->date_ptr,head->size);
	return;
}

void delete()
{
	if(head == NULL)
		puts("nonono");
	else
	{
		free(head->date_ptr);
		free(head);
		head = head->next;
		puts("delete success");
	}
	return;
}

void show()
{
	if(head != NULL)
	{
		printf("Content: %s\n", head->date_ptr);
	}
	else
		puts("nonono");
	return;
}

void edit()
{

	if(head != NULL)
	{
		read(0, head->date_ptr, (head->size)+0x10);
	}
	else
		puts("nonono");
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
			}
			
		}
}
