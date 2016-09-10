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
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <fnmatch.h>
const int long_size = sizeof(long);
struct sandbox {
  pid_t child;
  const char *progname;
};

struct sandb_syscall {
  int syscall;
  void (*callback)(struct sandbox*, struct user_regs_struct *regs);
};

struct sandb_syscall sandb_syscalls[] = {
  {__NR_read,            NULL},
  {__NR_write,           NULL},
  {__NR_exit,            NULL},
  {__NR_brk,             NULL},
  {__NR_mmap,            NULL},
  {__NR_access,          NULL},
  {__NR_open,            NULL},
  {__NR_fstat,           NULL},
  {__NR_close,           NULL},
  {__NR_mprotect,        NULL},
  {__NR_munmap,          NULL},
  {__NR_arch_prctl,      NULL},
  {__NR_exit_group,      NULL},
  {__NR_getdents,        NULL},
};

void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}
int checkperms(char *perm,int mode){
	errno=13;
	if((mode&O_ACCMODE)==0|(mode&O_ACCMODE)==2)
		if(perm[0]=='1')
			printf("Read Permission good!\n");
		else{
			fprintf(stderr, "EACCESS %s: System Call Bypassed\n", strerror(errno));return 0;
		}
	if((mode&O_ACCMODE)==1|(mode&O_ACCMODE)==2)
		if(perm[1]=='1')
			printf("Write Permission good!\n");
		else
		{	fprintf(stderr, "EACCESS %s: System Call Bypassed\n", strerror(errno));return 0;}
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

void pattern_match(char *p,FILE *f,int mode,struct sandbox *sandb){
	char* line=malloc(100);
	char* perm=malloc(20);
	char* foundperm=malloc(20);
	char* pattern=malloc(20);
	int match=0;
	while (fgets(line, 100, f)!=NULL ) {
		perm=strtok(line," ");
		pattern=strtok(NULL," ");
		if(fnmatch(pattern,p,0)==0){
			printf("%s matched with %s!\n",p,pattern);
			strcpy(foundperm,perm);
			match=1;
		}
    }
	if(match==1){
		checkperms(foundperm,mode);
		//if(checkperms(foundperm,mode)==0);
		  //set regs to getpid() to bypass system call
	
	}
	//rewind(f);
}
int entry_flag=1;
void sandb_handle_syscall(struct sandbox *sandb,FILE *f) {
  
  int i;
  struct user_regs_struct regs;
  int syscall;
  char line[100];
 
  char *path;
  
  if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
    err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");
  syscall=regs.orig_rax;
  
  if(syscall == __NR_open) {
	if(entry_flag==1){
		get_path(sandb->child,regs.rdi,&path);
		//printf("%s %zu\n",path,strlen(path));	
		pattern_match(path,f,regs.rsi,sandb);
		rewind(f);
		entry_flag=0;
		
		}	

	else
		entry_flag=1;
	
  }
	//free(line)'
    //err(EXIT_FAILURE,"File traversal done, exiting now.\n");
	//exit(EXIT_FAILURE);
	
	 
  
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
  //Have to change this call if -c is used
  if(fp==NULL)
	  printf("WHUT");
  if(strcmp(argv[1], "-c")!=0)
	sandb_init(&sandb, argc-1, argv+1);
  else
	sandb_init(&sandb, argc-3, argv+3);  
  for(;;) {
	
    sandb_run(&sandb,fp);
	
  }
  

  
  return EXIT_SUCCESS;
}