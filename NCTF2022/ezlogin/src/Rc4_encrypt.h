#include<bits/stdc++.h>
using namespace std;
string trans(int num)//将明文每个字符形成的ascii码转换成十六进制的字符串。  如97转化成61 
{
	string p="";
	string q="";
	string x="0123456789abcdef";
	while(num)
	{
		p+=x[num%16];
		num/=16;
	}
	if(p.length()==1){
		p+="0";
	}
	for(int i=0;i<p.length();i++)
	{
		q+=p[p.length()-i-1];
	}
	return q;
}
void rc4_init(unsigned char *s,char *k,string key,int len)
{
	int j=0;
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
string rc4_crypt(unsigned char *s,string content,int Len) 
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
		p=content[k]^s[t];
		m+=trans(p);
	}
	
	return m;
}
string rc4_encrypt(string content)
{
	char k[256];
	unsigned char s[256];
	int len;//密钥长度 
	int Len;//明文长度 
	string key;
	string encrypted_content;
	cout<<"Please enter the key:"<<endl;
	cout<<"> ";
	cin>>key;
	len=key.length();
	rc4_init(s,k,key,len);
	Len=content.length();
	encrypted_content=rc4_crypt(s,content,Len);
	return encrypted_content;
}
