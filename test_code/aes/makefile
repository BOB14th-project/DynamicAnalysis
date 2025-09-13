# Makefile for aes project

CC=gcc
CXX=g++
CFLAGS=-Wall -O2
CXXFLAGS=-Wall -O2




# Targets
all: aes.o test_c



aes.o: aes.c aes.h
	$(CC) $(CFLAGS) -c aes.c -o aes.o

test_c: test.c aes.o aes.h
	$(CC) $(CFLAGS) -o $@ test.c aes.o


clean:
	rm -f test_c *.o *.obj *.ilk *.pdb *.log

.PHONY: all clean