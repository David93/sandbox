#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <fnmatch.h>
const int long_size = sizeof(long);
int entry_flag=1;
struct sandbox {
  pid_t child;
  const char *progname;
};
void get_path(pid_t,long,char**);
int pattern_match(char*,FILE*, char**);
struct sandb_syscall {
  int syscall;
  void (*callback)(struct sandbox* sandb, struct user_regs_struct regs, FILE *f);
};
void openathandle(struct sandbox* sandb, struct user_regs_struct regs,FILE *f){
	char *path;
	char *res_path;
	char *perm;
	get_path(sandb->child,regs.rsi,&path);
	realpath(path,res_path);
	if(pattern_match(res_path,f,&perm)==1)
	{	
		if(checkperms_openat(perm,regs.rdx)==0){
			ptrace(PTRACE_POKEDATA, sandb->child, regs.rsi, "/root");
		}	}
	rewind(f);
		
}
void openhandle(struct sandbox* sandb, struct user_regs_struct regs,FILE *f){
	char *path;
	char *perm;
	char *res_path;
	get_path(sandb->child,regs.rdi,&path);
	realpath(path,res_path);
	//printf("%s\n",res_path);
	if(pattern_match(res_path,f,&perm)==1)
	{	
		
		if(checkperms_open(perm,regs.rsi)==0){
			
			ptrace(PTRACE_POKEDATA, sandb->child, regs.rdi, "/root");
		}	}
	rewind(f);
		
}
void handlecomp(char *name, FILE *f){
	
	char cwd[1024];
	char *perm;
	if(strstr(name,".")!=NULL){
    getcwd(cwd, sizeof(cwd));
	strcat(cwd,name+1);
	}
	else
		strcpy(cwd,name);
	
	errno=13;
	if(pattern_match(cwd,f,&perm) && perm[2]=='0'){
		fprintf(stderr, "EACCESS %s: Execution Denied\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}
void accesshandle(struct sandbox* sandb, struct user_regs_struct regs,FILE *f){
	char *path;
	char *perm;
	get_path(sandb->child,regs.rdi,&path);
	//printf("%s \n",path);
   
    if(pattern_match(path,f,&perm)==1)
	{	
		
	if(checkperms_access(perm,regs.rsi)==0){
			
			ptrace(PTRACE_POKEDATA, sandb->child, regs.rdi, "/root");
		}	}
	rewind(f);
	
}
void mkdirhandle(struct sandbox* sandb, struct user_regs_struct regs,FILE *f){
	
	char *path;
	char *perm;
	char cwd[1024];
    getcwd(cwd, sizeof(cwd));
	
	if(pattern_match(cwd,f,&perm) && perm[1]=='0')
	{	
		errno=13;
	    regs.orig_rax=__NR_getpid;
		ptrace(PTRACE_SETREGS, sandb->child, NULL, &regs);
		fprintf(stderr, "EACCESS %s: mkdir System Call Denied\n", strerror(errno));
	}
	rewind(f);
	
}

struct sandb_syscall sandb_syscalls[] = {
 // {__NR_link,        linkhandle},	
  {__NR_openat,      openathandle},
  {__NR_access,      accesshandle},
  {__NR_open,        openhandle},
  {__NR_mkdir,       mkdirhandle},
 
 
};

void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}
//Returns 0 if permission not available
int checkperms_open(char *perm,int mode){
	
	if((mode&O_ACCMODE)==0|(mode&O_ACCMODE)==2)
		if(perm[0]=='0')
		{
			printf("open System Call Bypassed\n");return 0;
		}
	if((mode&O_ACCMODE)==1|(mode&O_ACCMODE)==2)
		if(perm[1]=='0')
		{	printf("open System Call Bypassed\n");return 0;}
	return 1;
}
int checkperms_openat(char *perm,int mode){
	
	if((mode&O_ACCMODE)==0|(mode&O_ACCMODE)==2)
		if(perm[0]=='0')
			{
			printf("openat System Call Bypassed\n");return 0;
		}
	if((mode&O_ACCMODE)==1|(mode&O_ACCMODE)==2)
		if(perm[1]=='0')
		{	printf("openat System Call Bypassed\n");return 0;}
	return 1;
}
int checkperms_access(char *perm,int mode){
	
	if(mode=1 && perm[2]=='0')
	{	printf("access System Call Bypassed\n");return 0;}
	if(mode=2 && perm[1]=='0')
	{	printf("openat System Call Bypassed\n");return 0;}	
	if(mode=4 && perm[0]=='0')
	{	printf("openat System Call Bypassed\n");return 0;}	
	
	return 1;
}
void get_path(pid_t child, long addr,
             char **str){
	char laddr[100]="";
	*str=malloc(100);
	int i,j,k,flag;
	union u{
		long val;
		char chars[32];
	}data;
	i = 0;
	j=0;
	flag=0;
    while(1) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i *sizeof(long),
                          NULL);//getting path from user space, using address obtained earlier from address
     	++i;
        for(k=0;k<8;k++)
		{
			if(data.chars[k]=='\0')
			{flag=1;laddr[j]='\0';break;}
			laddr[j]=data.chars[k];
			j++;
		
		}	
		if(flag==1)
			break;
		
    }
	sprintf(*str,"%s",laddr);	
    
}


//Returns 1 if matched with last match for permissions
int pattern_match(char *p,FILE *f,char** foundperm){
	char* perm=malloc(20);
	*foundperm=malloc(20);
	char* pattern=malloc(20);
	int match=0;
	while (!feof(f) ) {
		fscanf(f,"%s %s",perm,pattern);
		//printf("%s\n",pattern);
		if(fnmatch(pattern,p,FNM_PATHNAME)==0){
			//printf("%s matched with %s!\n",p,pattern);
			strcpy(*foundperm,perm);
			match=1;
		}
    }
	return match;
	
}

void sandb_handle_syscall(struct sandbox *sandb,FILE *f) {
  
  int i;
  struct user_regs_struct regs;
  int syscall;
  
  
  if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
    err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");
  syscall=regs.orig_rax;
   
  for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
    if(regs.orig_rax == sandb_syscalls[i].syscall) {
      if(sandb_syscalls[i].callback != NULL && entry_flag==1){
        sandb_syscalls[i].callback(sandb, regs, f);
		entry_flag=0;
	  }
	  else
		entry_flag=1;
      return;
    }
  }
  	
	 
  
  //return;
  
  
  /*
  if(regs.orig_rax == -1) {
    printf("[SANDBOX] Segfault ?! KILLING !!!\n");
  } else {
    printf("[SANDBOX] Trying to use devil syscall (%llu) ?!? KILLING !!!\n", regs.orig_rax);
  }
  */
 
}

void sandb_init(struct sandbox *sandb, int argc, char **argv) {
  pid_t pid;
 
  pid = fork();
  if(pid == -1)
    err(EXIT_FAILURE, "[SANDBOX] Error on fork:");
   if(pid == 0) {
	
    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME:");
	
    if(execvp(argv[0], argv) < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to execv:");

  } else {
	
    sandb->child = pid;
    sandb->progname = argv[0];
    wait(NULL);
  }
}

void sandb_run(struct sandbox *sandb, FILE *f) {
  int status;
  
  if(ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL) < 0) {
    if(errno == ESRCH) {
      waitpid(sandb->child, &status, __WALL | WNOHANG);
	  
      sandb_kill(sandb);
    } else {
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
    }
  }

  wait(&status);

  if(WIFEXITED(status)){
    exit(EXIT_SUCCESS);

  }
  if(WIFSTOPPED(status)) {
	
	
    sandb_handle_syscall(sandb,f);
    
  }
}

int main(int argc, char **argv) {
  struct sandbox sandb;
  int i;
  FILE *fp=NULL;
  char ch;
  
  if ( argc >1 && strcmp(argv[1], "-c") == 0 )  /* Process optional arguments. */
  {
	fp = fopen(argv[2], "r");
	
  }
  if(fp==NULL)
  {
	fp = fopen(".fendrc", "r");
	
	if(fp==NULL)
	{
		
		struct passwd *pw = getpwuid(getuid());
		fp = fopen(strcat(pw->pw_dir,"/.fendrc"),"r");
		if(fp==NULL)
		{
			printf("Must provide a config file.\n");
			exit(EXIT_FAILURE);
		}
	}
  }/*
  
  if(argc < 2) {
    errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
  }
 */
  
  if(strcmp(argv[1], "-c")!=0){
	if(strstr(argv[1],"/")!=NULL)
	   handlecomp(argv[1],fp);
	   sandb_init(&sandb, argc-1, argv+1);
  }
  else{
	if(strstr(argv[3],"/")!=NULL)
	   handlecomp(argv[3],fp);
	   sandb_init(&sandb, argc-3, argv+3);  
  }
  for(;;) {
	
    sandb_run(&sandb,fp);
	
  }
  

  
  return EXIT_SUCCESS;
}