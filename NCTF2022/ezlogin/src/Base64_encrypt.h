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
}//ÿ6��Ϊһ�飬��6����������ת��ʮ���Ʋ�����Ϊ�±�Ѱ��table����ַ� 
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
	} //��21-31���������ı�����жϣ����ȱ������64�������������롣 
	int table1[1000];//�洢���������ݡ� 
	int n;//�洢�û�������ַ������� 
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
		
	}//��38-46 forѭ�����û�������ַ���ת���ɶ����Ʋ��Ҵ洢��table1���� 
	switch( (n%3) )//�жϳ����Ƿ�Ϊ3�ı�������������Ӽ���0�Լ����ļ�=�ŵĸ��� 
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
			table1[8*n+3]=0;//��0�ճ�6�ı��� 
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
