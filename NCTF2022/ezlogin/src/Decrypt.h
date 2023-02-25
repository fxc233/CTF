#include<iostream>
#include "Menu2.h"
#include "Xor_decrypt.h" 
#include "Base64_decrypt.h"
#include "Caesar_decrypt.h"
#include "Tea_decrypt.h"
#include "Rc4_decrypt.h"

using namespace std;

/*
用来进行解密的大函数，分支有不同的解密函数 
*/

void decrypt(string content)
{
	int ch = menu2();
	string decrypted_content;
	
	switch(ch)
	{
		case 1:
			decrypted_content = xor_decrypt(content);
			break;
		case 2:
			decrypted_content = caesar_decrypt(content);
			break;
		case 3:
			decrypted_content = base64_decrypt(content);
			break;
		case 4:
			decrypted_content = tea_decrypt(content);
			break;
		case 5:
			decrypted_content = rc4_decrypt(content);
			break;
		default:
			break;
	}

	
	if(decrypted_content != "invalid")
	{
		cout << "The decrypted ciphertext is:" << endl;
		cout << decrypted_content << endl;
	}
	cout << "Press Enter to return to the main menu" << endl << endl;
}
