all: fend.c
	gcc -o fend.o fend.c
clean:
	rm *.o