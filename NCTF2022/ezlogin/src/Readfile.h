#include<iostream>
#include<fstream>
#include<bits/stdc++.h>

using namespace std;

/*
读取文件函数：用来读取文件里的内容，并返回int类型的数值来让主函数判断是否读取成功 
*/

int Read_file(string *content)
{
	fstream infile;
	char buf;

	infile.open("./1.txt");
	if (infile.is_open())
		cout << endl << "[+] open file success!" << endl;
	else
	{
		cout << "[-] open file error!" << endl;
		return 0;
	}
	
	*content = "";

	while((buf = infile.get())!=EOF)
	{
		//cout << buf;
		*content += buf;
	}
	
	//cout << endl;
	cout << "[+] read file success!" << endl;
	cout << "The content to be encrypted/decrypted is:" << endl;
	cout << *content << endl << endl;

	return 1;
}
