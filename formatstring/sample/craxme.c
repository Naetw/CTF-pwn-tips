#include <stdio.h>

int magic = 0 ;

int main(){
	char buf[0x100];
	setvbuf(stdout,0,2,0);
	puts("Please crax me !");
	printf("Give me magic :");
	read(0,buf,0x100);
	printf(buf);
	if(magic == 0xda){
		system("cat /home/craxme/flag");
	}else if(magic == 0xfaceb00c){
		system("cat /home/craxme/craxflag");
	}else{
		puts("You need be a phd");
	}

}
