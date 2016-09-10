#include<stdlib.h>
#include<stdio.h>
#include<fnmatch.h>

#include<string.h>


int main(int argc, char **argv) {
	
	char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    printf("%s", cwd);
   
   return 0;
}