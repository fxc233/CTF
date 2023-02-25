#include<iostream>
#include<fstream>
#include<string.h>
using namespace std;

/*
菜单一：用来提示用户输入所需要的功能是加密还是解密 
*/

int menu1()
{
	unsigned int choose;
	char ch;
	char *buf = (char*)malloc(0x1000);
	ofstream outfile;
	outfile.open("./1.txt");
	if (outfile.is_open())
		cout << endl << "[+] open file success!" << endl;
	else
	{
		cout << "[-] open file error!" << endl;
		return 0;
	}
	
	/*


  _____                             _   _                               _       _                            _   _                                 _      _   
 | ____|_ __   ___ _ __ _   _ _ __ | |_(_) ___  _ __     __ _ _ __   __| |   __| | ___  ___ _ __ _   _ _ __ | |_(_) ___  _ __     __ _ _ __  _ __ | | ___| |_ 
 |  _| | '_ \ / __| '__| | | | '_ \| __| |/ _ \| '_ \   / _` | '_ \ / _` |  / _` |/ _ \/ __| '__| | | | '_ \| __| |/ _ \| '_ \   / _` | '_ \| '_ \| |/ _ \ __|
 | |___| | | | (__| |  | |_| | |_) | |_| | (_) | | | | | (_| | | | | (_| | | (_| |  __/ (__| |  | |_| | |_) | |_| | (_) | | | | | (_| | |_) | |_) | |  __/ |_ 
 |_____|_| |_|\___|_|   \__, | .__/ \__|_|\___/|_| |_|  \__,_|_| |_|\__,_|  \__,_|\___|\___|_|   \__, | .__/ \__|_|\___/|_| |_|  \__,_| .__/| .__/|_|\___|\__|
                        |___/|_|                                                                 |___/|_|                             |_|   |_|               
                                                                                                                                                              
	*/ 

	cout << "Please enter your desired function" << endl;
	cout << "1.encrypt" << endl; //加密 
	cout << "2.decrypt" << endl; //解密 
	cout << "3.exit" << endl;
	cout << ">> ";

	cin >> choose;
	if(choose >= 3 || choose == 0)
		return choose;

	cout << endl;
	cout << "Please put the content you want to encrypt into '1.txt' " << endl;

a:
	cin >> buf;
	outfile << buf << endl;
	cout << "When you finish  please input 'Y'" << endl;

	cin >> ch;
	if(ch == 'Y')
		return choose;
	else
		goto a;
}
