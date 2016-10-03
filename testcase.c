#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
/* Y means the access is granted, N means the access is denied. */
char access_granted[] = "Y";
char access_denied[] = "N";

void myPrintAllCases(int f, int errsv) {
    if (f == -1) {
    printf("Recieved error=%d\n",errsv);
	if (errsv == EACCES) {
            printf("fs\n");
        }
	else {
            printf("fn\n");
	}
    }
    else {
       printf("a\n");
    }
}

void open_r(char* filename) {
    int f = open(filename, O_RDONLY);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
    close(f);
}

void open_rw(char* filename) {
    int f = open(filename, O_RDONLY|O_WRONLY);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
    close(f);
}

void open_rwc(char* filename) {
    int f = open(filename, O_RDWR|O_CREAT);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
    close(f);
}

void open_rc(char* filename) {
    int f = open(filename, O_RDONLY|O_CREAT);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
    close(f);
}

void openat_r(char* filename) {
    int para = open("./", O_RDONLY);
    int f = openat(para, filename, O_RDONLY);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
    close(para);
    close(f); 
}

void openat_rw(char* filename) {
    int para = open("./", O_RDONLY);
    int f = openat(para, filename, O_RDONLY | O_WRONLY);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
    close(para);
    close(f); 
}

void openat_rwc(char* filename) {
    int para = open("./", O_RDONLY);
    int f = openat(para, filename, O_RDWR | O_CREAT);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
    close(para);
    close(f); 
}

void openat_rc(char* filename) {
    int para = open("./", O_RDONLY);
    int f = openat(para, filename, O_RDONLY | O_CREAT);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
    close(para);
    close(f); 
}

void creat_rc(char* filename) {
    int f = creat(filename, O_RDONLY|O_CREAT);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
    close(f);
}

void creat_rwc(char* filename) {
    int f = creat(filename, O_RDWR|O_CREAT);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
    close(f);
}


void test_unlink(char* filename) {
    int f = unlink(filename);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
}


void test_stat(char* filename) {
    struct stat buf;
    int f = stat(filename, &buf);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
}


void test_faccessat(char *filename) {
    int f = faccessat(AT_FDCWD, filename, R_OK, AT_EACCESS);        
    int errsv = errno;
    myPrintAllCases(f, errsv);
}

void linkTest(const char *oldpath, const char *newpath) {
    int f = link(oldpath, newpath);
    int errsv = errno;
    myPrintAllCases(f, errsv);
}

int main(int argc, char* argv[]) {
    if (strcmp(argv[1], "open_r") == 0) {
        open_r(argv[2]);
    }   
    else if (strcmp(argv[1], "open_rw") == 0) {
        open_rw(argv[2]);
    }
    else if (strcmp(argv[1], "open_rwc") == 0) {
        open_rwc(argv[2]);
    }
    else if (strcmp(argv[1], "open_rc") == 0) {
        open_rc(argv[2]);
    }
    else if (strcmp(argv[1], "openat_r") == 0) {
        openat_r(argv[2]);
    }   
    else if (strcmp(argv[1], "openat_rw") == 0) {
        openat_rw(argv[2]);
    }
    else if (strcmp(argv[1], "openat_rwc") == 0) {
        openat_rwc(argv[2]);
    }
    else if (strcmp(argv[1], "openat_rc") == 0) {
        openat_rc(argv[2]);
    }
    else if (strcmp(argv[1], "creat_rc") == 0) {
        creat_rc(argv[2]);
    }
    else if (strcmp(argv[1], "creat_rwc") == 0) {
        creat_rwc(argv[2]);
    }
    else if (strcmp(argv[1], "unlink") == 0) {
        test_unlink(argv[2]);
    }
    else if (strcmp(argv[1], "stat") == 0) {
        test_stat(argv[2]);
    }
    else if (strcmp(argv[1], "faccessat") == 0) {
        test_faccessat(argv[2]);
    }
    else  if (strcmp(argv[1], "link_new_all") == 0)
    {
    	 linkTest(argv[2], argv[3]);
    }
    return 1;
}

