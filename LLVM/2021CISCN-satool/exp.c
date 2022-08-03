#include <stdio.h>

int save(char* a, char* b){return 0;}
int takeaway(char* a){return 0;}
int stealkey(){return 0;}
int fakekey(long long a){return 0;}
int run(){return 0;}

int B4ckDo0r(){
	save("FXC", "FXC");
	save("FXC", "FXC");
	save("FXC", "FXC");
	save("FXC", "FXC");
	save("FXC", "FXC");
	save("FXC", "FXC");
	save("FXC", "FXC");
	
	save("\x00", "FXC");
	stealkey();
	fakekey(-0x1090F2);
	run();
	return 0;
}
