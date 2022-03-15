BUILD_DIR = $(shell pwd)
CC ?= gcc
CFLAG:=-g 
CFLAG+=-Wall
CFLAG+=-O2

all:
	$(CC) -o test des.c $(CFLAG)

clean:
	rm -f test

indent:
	clang-format -i *.[ch]
