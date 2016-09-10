#include<stdlib.h>
#include<stdio.h>
#include<fnmatch.h>
void retstring(char **a){
	char b[100]="lol";
	*a=malloc(100);
	//*a=b;
	sprintf(*a,"%s",b);
	
}



int main(int argc, char **argv) {
	
	char *res;
	retstring(&res);
	//printf("%s\n",res);
	printf("%d\n",fnmatch("l*","lol",FNM_PATHNAME));
}