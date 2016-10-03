all: fend.c testcase.c
	gcc -o fend fend.c
	gcc -o testcase testcase.c
clean:
	rm fend