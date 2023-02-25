#include<bits/stdc++.h>
using namespace std;
string trans1(string content)//将明文的每两个为一组，强制转换成ascii码 
{
	string str="";
	char p;
	string table="0123456789abcdef";
	int n=content.length()/2;
	for(int i=0;i<n;i++)
	{
		p=16*table.find(content[2*i])+table.find(content[2*i+1]);
		str+=p;
	}
	return str;
}
void rc4_init1(unsigned char *s,char *k,string key)
{
	int j=0;
	int len=key.length();
	for(int i=0;i<256;i++)
	{
		s[i]=i;
		k[i]=key[i%len];
	}
	for(int i=0;i<256;i++)
	{
		j=(j+s[i]+k[i])%256;
		swap(s[i],s[j]);
	}
}
string rc4_crypt1(unsigned char *s,string content,int Len)
{
	string m="";
	int p;
	int i=0,j=0,t=0;
	for(int k=0;k<Len;k++)
	{
		i=(i+1)%256;
		j=(j+s[i])%256;
		swap(s[i],s[j]);
		t=(s[i]+s[j])%256;
		m+=content[k]^s[t];
	}
	
	return m;
}
string rc4_decrypt(string content)
{
	char k[256];
	unsigned char s[256];
	int Len;
	string key;
	string decrypted_content;
	cout<<"Please enter the key:"<<endl;
	cout<<"> ";
	cin>>key;
	rc4_init1(s,k,key);
	Len=content.length()/2;
	content=trans1(content);
	decrypted_content=rc4_crypt1(s,content,Len);
	return decrypted_content;
}
