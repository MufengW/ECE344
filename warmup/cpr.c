#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "common.h"

/* make sure to use syserror() when a system call fails. see common.h */

const int BUFF_SIZE = 4096;
void copy_file();
void copy_dir();

void
usage()
{
	fprintf(stderr, "Usage: cpr srcdir dstdir\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	if (argc != 3) {
		usage();
	}
	char* src_file = argv[1];
	char* dst_file = argv[2];
	copy_dir(src_file, dst_file);
	return 0;
}

//handles the copy of a single file
void copy_file(char* src_file, char* dst_file) {

	//source file and destination file descriptor
	int src_fd = 0;
	int dst_fd = 0;

	//open source file with read only access, file should already exists
	src_fd = open(src_file, O_RDONLY);
	if(src_fd < 0) syserror(open,src_file);

	//create destination file with read, write and exicute access, should not exist before
	dst_fd = creat(dst_file, S_IRWXU);
	if(dst_fd < 0) syserror(creat,dst_file);

	int read_rt = 0;
	int write_rt = 0;
	char buf[BUFF_SIZE];
	memset(buf,0,BUFF_SIZE * sizeof(char));

	do {
		read_rt = read(src_fd, buf, BUFF_SIZE);
		if(read_rt < 0) syserror(read,src_file);

		write_rt = write(dst_fd, buf, read_rt);
		if(write_rt < 0) syserror(write,dst_file);

	} while (read_rt!=0); //stop until there is nothing to read

	if(close(src_fd) < 0) syserror(close, src_file);
	if(close(dst_fd) < 0) syserror(close, dst_file);
}

void copy_dir(char* src_dir, char* dst_dir){

	//get stats of the source input, whether it is a file or a directory, and it's w/r/x permisson
	struct stat src_dir_stat;
	if(stat(src_dir, &src_dir_stat) < 0) syserror(stat,src_dir);

	//directly use the copy_file function if the input soure is a file
	if(S_ISREG(src_dir_stat.st_mode)){
		copy_file(src_dir,dst_dir);
		if(chmod(dst_dir,src_dir_stat.st_mode)) syserror(chmod,dst_dir); // set the same permisson for the copied file
		return;
	}

	// if the input source is a directory, then need to traverse through the whole directory recursively.
	
	if(mkdir(dst_dir,S_IRWXU)) syserror(mkdir,dst_dir); // make corresponding sub directory

	// tmp strings to store the current working directory
	char tmp_src_dir[1000] = "";
	char tmp_dst_dir[1000] = "";

	// pointing to current working directory
	DIR* src_dir_ptr = opendir(src_dir);

	//pointing to current working sub directory
	struct dirent* sub_dir = readdir(src_dir_ptr);

	// traverse through the sub directory
	while(sub_dir != NULL) {
		char* sub_file = sub_dir->d_name;
		if(strcmp(sub_file,".")!=0 && strcmp(sub_file,"..")!=0) { // skip the . and .. directory

			// construct new sub directory in tmp_src_dir and tmp_dst_dir
			strcpy(tmp_src_dir,src_dir);
			strcpy(tmp_dst_dir,dst_dir);
			strcat(strcat(tmp_src_dir,"/"),sub_file);
			strcat(strcat(tmp_dst_dir,"/"),sub_file);
			copy_dir(tmp_src_dir,tmp_dst_dir);
		}
		sub_dir = readdir(src_dir_ptr);
	}
	if(chmod(dst_dir,src_dir_stat.st_mode)) syserror(chmod,dst_dir); // set the same permisson for the copied directory
	if(closedir(src_dir_ptr) < 0) syserror(closedir, src_dir);
}
