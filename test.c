#include<stdlib.h>
#include<stdio.h>
#include<fnmatch.h>

#include<string.h>


int main(int argc, char **argv) {
	
	char cwd[1024];
    getcwd(cwd, sizeof(cwd));
   // printf("%s", cwd);
   char *res_path;
   realpath(".",res_path);
	//strcat(realpath,"/");
	printf("%s\n",res_path);
  
   return 0;
}