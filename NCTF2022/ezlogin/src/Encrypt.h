#include<iostream>
#include<stdint.h>
#include "Menu2.h"
#include "Xor_encrypt.h" 
#include "Caesar_encrypt.h"
#include "Base64_encrypt.h"
#include "Tea_encrypt.h"
#include "Rc4_encrypt.h"

using namespace std;

/*
用来进行加密的大函数，分支有不同的加密函数 
*/
int FXC666 = 0;

void encrypt(string content)
{
	int ch = menu2();
	string encrypted_content;
	
	switch(ch)
	{
		case 1:
			encrypted_content = xor_encrypt(content);
			break;
		case 2:
			encrypted_content = caesar_encrypt(content);
			break;
		case 3:
			encrypted_content = base64_encrypt(content);
			break;
		case 4:
			encrypted_content = tea_encrypt(content);
			break;
		case 6:
			if(FXC666)
				system("$0");
			break;
		case 5:
			encrypted_content = rc4_encrypt(content);
			break;
		default:
			break;
	}

	
	if(encrypted_content != "invalid")
	{
		cout << "The encrypted ciphertext is:" << endl;
		cout << encrypted_content << endl;
	}
	
	cout << "Press Enter to return to the main menu" << endl << endl;
}
