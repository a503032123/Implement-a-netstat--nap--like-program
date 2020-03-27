CC = gcc


CFLAGS = -I. -Wall
abc: udp.c transform.o transformv6.o
	$(CC) udp.c transform.o transformv6.o -o abc

transform.o: transform.c
	$(CC) -c transform.c
transformv6.o: transformv6.c
	$(CC) -c transformv6.c
clean:
	rm *.o abc
