#include<iostream>
#include<stdint.h>
#include<stdlib.h>
#include<cstring>
#include<string>

using namespace std;

string tea_decrypt(string content)
{
	string encrypted_content = "";
	uint32_t v0, v1, sum = 0xC6EF3720;                       /* set up */
	uint32_t delta = 0x9e3779b9;                             /* a key schedule constant */
	uint32_t k0, k1, k2, k3;                                 /* cache key */
    
	int s1[0x50];
	uint32_t v[0x10];
	
	char *ptr;
	
	memset(s1,0,sizeof(s1));
	memset(v,0,sizeof(v));
	
	int num = 0;
	int i = 0;
	int j = 0;
	
	content+= " ";
	//cout << content << endl;

	while(1)
	{
		if(content.find(" ") != -1)
		{
			for(j=0; j<content.length(); j++)
				ptr[j] = content[j];
			ptr[j]='0';
			//cout << ptr << endl;
			sscanf(ptr,"%lx",&v[i]);
			content = content.substr(content.find(" ")+1,content.length());
			num++;
			i++;
			//cout << content << endl;
		}
		else
			break;
	}
	
	/*
	
	for(i=0; i<num; i++)
	{
		cout << (uint32_t*)v[i] << " ";
	}
	
	cout << endl;
	*/
	//cout << num << endl;

	cout << "Please enter the encrypted key you want" << endl;
	cout << "the encrypted key must be four hexadecimal numbers " << endl;
	cout << "for example: 0x10 0x20 0x30 0x10 " << endl;
	cout << "> ";
	getchar();
	scanf("0x%lx 0x%lx 0x%lx 0x%lx", &k0, &k1, &k2, &k3);
	//cout << k0 << " " << k1 << " " << k2 << " " << k3 << " "<< endl;
	
	cout << "The decrypted ciphertext is:" << endl;
	
	for(int k=0; k<num; k+=2)
	{
		v0 = v[k]; v1 = v[k+1];
		
		//cout << (uint32_t*)v0 << " " << (uint32_t*)v1 << endl;
		sum = 0xC6EF3720;
		
		for (i=0; i<32; i++)
		{                         /* basic cycle start */
	        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
	        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
	        sum -= delta;                                   
	    }                                              /* end cycle */
	    v[k] = v0; v[k+1] = v1;
	    
	    cout << (uint32_t*)v[k] << " " << (uint32_t*)v[k+1] << " ";
	}
    
	cout << endl;
	
	return "invalid";
}
