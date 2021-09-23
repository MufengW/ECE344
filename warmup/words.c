#include "common.h"

int
main(int argc, char **argv)
{
	int wc=1;
	while(argc>1){
		printf("%s\n",argv[wc]);
		++wc;
		--argc;
	}
	return 0;
}
