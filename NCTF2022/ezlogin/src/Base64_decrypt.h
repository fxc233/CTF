#include<bits/stdc++.h>
using namespace std;
int *trans(int w,string table,string content)
{
	int p;
	int table1[1000];
	for(int i=0;i<w;i++)
	{
		p=table.find( content[i] );//Ѱ���±� 
		for(int j=0;j<6;j++)
		{
			table1[6*i+5-j]=(p & 1);
			p=p>>1;
		}//�±�ת�ɶ����������Ҵ�����顣 
	}
	return table1;
}
string trans1(int x,int *table1)
{
	string ec="";
	char k;
	int p;
	for(int i=0;i<x;i++)
	{
		p=128*table1[8*i]+64*table1[8*i+1]+32*table1[8*i+2]+16*table1[8*i+3]+8*table1[8*i+4]+4*table1[8*i+5]+2*table1[8*i+6]+1*table1[8*i+7];//8��Ϊһ�飬�Ѷ�����ת�������ġ� 
		k=p;
		ec+=k;
	}
	return ec;
}
string base64_decrypt(string content)
{
	y:
	cout<<"Please enter the table you want:  //the length must be 64."<<endl;
	cout<<"for example: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"<<endl;
	cout<<"> ";
	int w;//�����г�ȥ=�ŵ����� 
	string decrypted_content="";//���ܺ������ 
	int m;
	int n=content.length();//���ĳ��� 
	int *table1;//�洢����ת����Ķ����Ƴ��� 
	string table;
	cin>>table;
	if(table.length() !=64 )
	{
		cout<<"wrong length!"<<endl;
		cout<<"please enter again!"<<endl;
		goto y;
	}//��21-31���������ı�����жϣ����ȱ������64�������������롣
	if(content[n-1]=='=' && content[n-2]=='=')
	{
		w=n-2;
		table1=trans(w,table,content);
		m=(6*w-4)/8;
		decrypted_content=trans1(m,table1);
	}
	else if(content[n-1]=='=' && content[n-2]!='=')
	{
		w=n-1;
		table1=trans(w,table,content);
		m=(6*w-2)/8;
		decrypted_content=trans1(m,table1);
	}
	else
	{
		w=n;
		table1=trans(w,table,content);
		m=(6*w)/8;
		decrypted_content=trans1(m,table1);
	}//�ж��м���=�ţ�Ȼ��ʡ�Բ���ת�ɶ��������飬������ 
	return decrypted_content;
}



//ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
