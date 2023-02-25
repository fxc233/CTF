#include<iostream>

#ifndef _TEST_MENU2_H_
#define _TEST_MENU2_H_

using namespace std;

/*
菜单二：提供给用户用来选择加解密方法 
*/

int menu2()
{
	int choose;

	cout << "Please enter the method you need" << endl;
	cout << "1.xor" << endl;
	cout << "2.caesar" << endl;
	cout << "3.Base64" << endl;
	cout << "4.Tea" << endl;
	cout << "5.RC4" << endl;
	cout << ">> ";

	cin >> choose;

	return choose;
}

#endif
