#include<iostream>
#include<stdint.h>

using namespace std;

string tea_encrypt (string content)
{
	uint32_t v0, v1, sum = 0;                                /* set up */
	uint32_t delta = 0x9e3779b9;                             /* a key schedule constant */
	uint32_t k0, k1, k2, k3;                                 /* cache key */
    
	int s1[0x50];
	uint32_t v[0x10];
	
	memset(s1,0,sizeof(s1));
	memset(v,0,sizeof(v));
	
	int j = 0;
	int n = content.length();
	
	for(int i=0; i<n; i++)
	{
		//cout << (uint32_t*)content[i] << endl;
		if(content[i] == '*')
			content[i] = '\x00';
		*(char*)(s1+i) = (int)content[i];
	}
	
	//cout << v[0] << endl;
	
	for(int i=0; i<n; i++)
	{
		//cout << (uint32_t*)s1[i] << endl;
		//cout << (uint32_t*)((s1[i]) << (8*(3-(i%4)))) << endl;
		//cout << (uint32_t*)v[j] << endl;
		if(i%4 != 3)
			v[j] += ((s1[i]) << (8*(3-(i%4))));
		if(i%4 == 3)
		{
			v[j] += s1[i];
			//cout << (uint32_t*)v[j] << endl;
			j++;
		}
	}

	/*
	for(int i=0; i<j; i++)
	{
		cout << (uint32_t*)v[i] << endl;
	}
	*/
	
	cout << "Tips: Tea encrypt need the content to be 8 bytes or its integral multiple, else it will be wrong" << endl; // 12345678
	cout << "Please enter the encrypted key you want" << endl;
	cout << "the encrypted key must be four hexadecimal numbers " << endl;
	cout << "for example: 0x10 0x20 0x30 0x10 " << endl;
	cout << "> ";
	getchar();
	scanf("0x%lx 0x%lx 0x%lx 0x%lx", &k0, &k1, &k2, &k3);
	//cout << k0 << " " << k1 << " " << k2 << " " << k3 << " "<< endl;

	cout << "The encrypted ciphertext is:" << endl;

	for(int k=0; k<j; k+=2)
	{
		v0 = v[k]; v1 = v[k+1]; sum = 0;
		//cout << (uint32_t*)v0 << " " << (uint32_t*)v1 << endl;
	    for (int i=0; i < 32; i++)
		{                       					             /* basic cycle start */
	        sum += delta;
	        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
	        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
	    }                                                        /* end cycle */
	
	    v[k] = v0; v[k+1] = v1;

		cout << (uint32_t*)v[k] << " " << (uint32_t*)v[k+1] << " ";
	}

	cout << endl;

    return "invalid";
}
