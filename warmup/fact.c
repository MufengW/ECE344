#include "common.h"
#include <math.h>
#include <string.h>
int isInt();
int fact();
int
main(int argc, char** argv)
{
	if(argc!=2){
		printf("Huh?\n");
	}
	int rt = isInt(argv[1]);
	if(rt==0) printf("Huh?\n");
	else if(rt>12) printf("Overflow\n");
	else printf("%d\n",fact(rt));
	return 0;
}

int isInt(char* input){
	long unsigned int length = strlen(input);
	if(length==1) {
		int char2int = (int)input[0]-(int)'0';
		if(char2int < 0 || char2int > 9) return 0;
		else return char2int;
	} else {
		int num = 0;
		for(long unsigned int i = 0; i < length; ++i){
			int char2int = (int)input[i]-(int)'0';
			if(char2int < 0 || char2int > 9) return 0;
			else num+=char2int*pow(10,length-i-1);
		}
		return num;
	}
	return 0;
}

int fact(int num) {
	if(num==0) return 1;
	else return num*fact(num-1);
}
