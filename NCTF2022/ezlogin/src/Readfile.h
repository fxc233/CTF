#include<iostream>
#include<fstream>
#include<bits/stdc++.h>

using namespace std;

/*
��ȡ�ļ�������������ȡ�ļ�������ݣ�������int���͵���ֵ�����������ж��Ƿ��ȡ�ɹ� 
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
