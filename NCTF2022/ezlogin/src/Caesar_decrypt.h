#include<iostream>

using namespace std;

string caesar_decrypt(string content)
{
	int offset;
	string decrypted_content = "";
	char c1;
	while(1)
	{
		cout << "Please enter the decrypted displacement you use(1-25)" << endl;
		cout << "> ";
		cin >> offset;
		if(offset<1 || offset>25)
		{
			cout << "invalid offset" << endl;
			continue;
		}
		
		for(int i=0; i<content.length(); i++)
		{
			c1 = content[i]-offset;
			
			if((c1>='a' && c1<='z' && content[i]>='a' && content[i]<='z') || (c1>='A' && c1<='Z' && content[i]>='A' && content[i]<='Z'))
				decrypted_content+= c1;
			else
				decrypted_content+= c1+26;
		}
		
		return decrypted_content;
	}
}
