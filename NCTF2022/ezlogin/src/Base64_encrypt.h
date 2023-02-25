#include<bits/stdc++.h>
using namespace std;


string trans(int x,string ec,int *table1,string table)
{
	int w=x/6;
	char s;
	int p;
	for(int i=0;i<w;i++)
	{
		p=0;
		p=p+32*table1[6*i]+16*table1[6*i+1]+8*table1[6*i+2]+4*table1[6*i+3]+2*table1[6*i+4]+table1[6*i+5]; 
		ec+=table[p];
		
	}
	return ec;
}//每6个为一组，将6个二进制数转成十进制并且作为下标寻找table表的字符 
string base64_encrypt(string content)
{
	y:
	cout<<"Please enter the table you want:  //the length must be 64."<<endl;
	cout<<"for example: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"<<endl;
	cout<<"> ";
	string table;
	cin>>table;
	if(table.length() != 64)
	{
		cout<<"wrong length!"<<endl;
		cout<<"please enter again!"<<endl;
		goto y;
	} //行21-31负责对输入的表进行判断，长度必须等于64，否则重新输入。 
	int table1[1000];//存储二进制数据。 
	int n;//存储用户输入的字符串长度 
	int p;
	int x;
	string encrypted_content="";
	n=content.length();
	for(int i=0;i<n;i++)
	{
		p=content[i];
		for(int j=0;j<8;j++){
			table1[8*i+7-j]=(p & 1);
			p=p>>1;
		}
		
	}//行38-46 for循环将用户输入的字符串转换成二进制并且存储进table1数组 
	switch( (n%3) )//判断长度是否为3的倍数，决定后面加几个0以及密文加=号的个数 
	{
		case 0:
			x=8*n;
			encrypted_content=trans(x,encrypted_content,table1,table);
			break;
		case 1:
			x=8*n+4;
			table1[8*n]=0;
			table1[8*n+1]=0; 
			table1[8*n+2]=0;
			table1[8*n+3]=0;//加0凑成6的倍数 
			encrypted_content=trans(x,encrypted_content,table1,table);
			encrypted_content+="==";
			break;
		case 2:
			x=8*n+2;
			table1[8*n]=0;
			table1[8*n+1]=0;
			encrypted_content=trans(x,encrypted_content,table1,table);
			encrypted_content+="=";
			break;
	}
	return encrypted_content;
	
}


//ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
