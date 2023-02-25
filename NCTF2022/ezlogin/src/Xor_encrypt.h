#include<bits/stdc++.h>

using namespace std;

string xor_encrypt(string content)
{
	string encrypted_content="";
	int key;
	int p;
	char s;
	while(1)
	{
		cout<<"please enter your key:"<<endl;
		cout<<"//the key must be 0-9"<<endl;
		cout<<">";
		cin>>key;
		if(key<0 ||key>9)
		{
			cout<<"invalid key."<<endl;
			continue;
		}
		for(int i=0;i<content.length();i++)
		{
			p=content[i];
			s=p^key;
			//cout<<s<<endl;
			encrypted_content+=s;
		}
		return encrypted_content;
	}
	
}
