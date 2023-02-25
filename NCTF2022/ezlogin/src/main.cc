//g++ -no-pie -z norelro -static -o main main.cc
#include<stdlib.h>
#include<iostream>
#include<fstream>
#include<cstring>
#include "Readfile.h"
#include "Menu1.h"
#include "Encrypt.h"
#include "Decrypt.h"

using namespace std;

void welcome()
{
	char buf[0x10];
	cout << buf+0x19 << endl;
}

void init()
{
        setbuf(stdin, 0);
        setbuf(stdout, 0);
        setbuf(stderr, 0);
        welcome();
}

void backdoor()
{
	system("$0");
}

int main()
{
	string file_content;
	int choose;
	
	init();
	
	while(1)
	{
		choose = menu1();
		switch(choose)
		{
			case 1:
				if(!Read_file(&file_content))
					break;
				encrypt(file_content);
				break;
			case 2:
				if(!Read_file(&file_content))
					break;
				decrypt(file_content);
				break;
			case 3:
				cout << "exit success !" << endl;
				exit(0);
			default:
				cout << "invaild choice !\nenter to choose again" << endl;
				exit(0);
		}
	}
	
}
